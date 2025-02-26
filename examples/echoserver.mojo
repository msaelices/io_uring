import sys
from buffer import Buffer
from collections import InlineArray
from memory import UnsafePointer

from mojix.errno import Errno
from mojix.fd import Fd, OwnedFd, UnsafeFd
from mojix.io_uring import SQE64, IoUringSqeFlags
from mojix.net.socket import socket, bind, listen
from mojix.net.types import AddrFamily, SocketType, SocketAddrV4
from mojix.timespec import Timespec
from io_uring import IoUring, BufferRing, IoUringBufferRingEntry, WaitArg
from io_uring.op import Accept, Read, Write, Nop

alias BYTE = Int8
alias MAX_CONNECTIONS = 16
alias BACKLOG = 512 
alias MAX_MESSAGE_LEN = 2048
alias BUFFERS_COUNT = 8  # Must be power of 2
alias BUF_RING_SIZE = BUFFERS_COUNT

alias ACCEPT = 0
alias READ = 1
alias WRITE = 2

@value
struct ConnInfo:
    var fd: Int32
    var type: UInt16
    var bid: UInt32  # Buffer ID

    fn __init__(out self, fd: Int32, type: UInt16, bid: UInt32 = 0):
        self.fd = fd
        self.type = type
        self.bid = bid

    fn to_int(self) -> UInt64:
        """Pack ConnInfo into a 64-bit integer for user_data."""
        return (UInt64(self.fd) << 32) | (UInt64(self.type) << 16) | UInt64(self.bid)
        
    @staticmethod
    fn from_int(value: UInt64) -> Self:
        """Unpack ConnInfo from a 64-bit integer."""
        return Self(
            fd=Int32((value >> 32) & 0xFFFFFFFF),
            type=UInt16((value >> 16) & 0xFFFF),
            bid=UInt32(value & 0xFFFF)
        )


struct BufferMemory:
    """Manages the buffer memory for the server."""
    var _data: InlineArray[Int8, MAX_MESSAGE_LEN * BUFFERS_COUNT]
    var buffer_ring: BufferRing
    
    fn __init__(out self, buf_grp: UInt16) raises:
        """Initialize the buffer memory and buffer ring.
        
        Args:
            buf_grp: Buffer group ID to use.
        """
        self._data = InlineArray[Int8, MAX_MESSAGE_LEN * BUFFERS_COUNT](fill=0)
        self.buffer_ring = BufferRing(BUFFERS_COUNT, buf_grp)
        
        # Add all buffers to the ring
        for i in range(BUFFERS_COUNT):
            buffer_addr = UInt64(Int(self._data.unsafe_ptr()) + i * MAX_MESSAGE_LEN)
            self.buffer_ring.add_buffer(i, buffer_addr, UInt32(MAX_MESSAGE_LEN))
    
    fn get_buffer_pointer(self, idx: UInt16) -> UnsafePointer[BYTE]:
        """Get a pointer to a specific buffer.
        
        Args:
            idx: Buffer index.

        Returns:
            Unsafe pointer to the buffer.
        """
        return self._data.unsafe_ptr() + (idx * MAX_MESSAGE_LEN)
        

fn main() raises:
    """Run an echo server using io_uring with ring mapped buffers."""
    args = sys.argv()
    port = Int(args[1]) if len(args) > 1 else 8080
    
    # Initialize io_uring instance with 128 entries
    ring = IoUring[](sq_entries=128)
    
    # Buffer group ID
    buf_grp_id = UInt16(1)
    
    # Create buffer memory and register the buffer ring
    var buffer_memory = BufferMemory(buf_grp_id)
    _ = buffer_memory.buffer_ring.register(ring.fd)
    
    # Setup listener socket
    listener_fd = socket(AddrFamily.INET, SocketType.STREAM)
    
    bind(listener_fd, SocketAddrV4(0, 0, 0, 0, port=port))
    listen(listener_fd, backlog=BACKLOG)
    print("Echo server listening on port", port)

    # Add initial accept
    var sq = ring.sq()
    if sq:
        conn = ConnInfo(fd=Int32(listener_fd.unsafe_fd()), type=ACCEPT)
        _ = Accept(sq.__next__(), listener_fd).user_data(conn.to_int())

    # Track active connections
    var active_connections = 0

    # Main event loop
    while True:
        # Submit and wait for at least 1 completion
        submitted = ring.submit_and_wait(wait_nr=1)
        
        # Process completions
        for cqe in ring.cq(wait_nr=0):
            res = cqe.res
            user_data = cqe.user_data
            
            if res < 0:
                print("Error:", res)
                continue

            conn = ConnInfo.from_int(user_data)
            
            # Handle accept completion
            if conn.type == ACCEPT:
                # New connection
                client_fd = Fd(unsafe_fd=res)
                active_connections += 1
                print("New connection: fd=", client_fd.unsafe_fd(), " (active: ", active_connections, ")")
                
                # Add read for the new connection
                sq = ring.sq()
                if sq:
                    read_conn = ConnInfo(fd=client_fd.unsafe_fd(), type=READ)
                    _ = Read[type=SQE64, origin=__origin_of(sq)](
                        sq.__next__(), 
                        client_fd, 
                        UnsafePointer[BYTE](), # Ring buffer will be selected by the kernel
                        UInt(MAX_MESSAGE_LEN)
                    ).user_data(read_conn.to_int()).sqe_flags(IoUringSqeFlags.BUFFER_SELECT).buf_group(buf_grp_id)
                
                # Re-add accept
                sq = ring.sq()
                if sq:
                    accept_conn = ConnInfo(fd=listener_fd.unsafe_fd(), type=ACCEPT)
                    _ = Accept(sq.__next__(), listener_fd).user_data(accept_conn.to_int())
            
            # Handle read completion
            elif conn.type == READ:
                if res <= 0:
                    # Connection closed or error
                    active_connections -= 1
                    print("Connection closed: fd=", conn.fd, " (active: ", active_connections, ")")
                else:
                    # Get buffer info from the CQE flags
                    # The high 16 bits of flags contain the buffer_id
                    buffer_id = UInt32(cqe.flags.value >> 16)
                    # Parse buffer ID to get group and index
                    (grp, idx) = BufferRing.parse_buffer_id(buffer_id)
                    
                    bytes_read = Int(res)
                    print("Read completion: fd=", conn.fd, " bytes=", bytes_read, " idx=", idx)
                    
                    # Get the buffer pointer
                    buff_ptr = buffer_memory.get_buffer_pointer(idx)
                    
                    # Echo data back
                    sq = ring.sq()
                    if sq:
                        write_conn = ConnInfo(fd=conn.fd, type=WRITE, bid=buffer_id)
                        _ = Write[type=SQE64, origin=__origin_of(sq)](
                            sq.__next__(), 
                            Fd(unsafe_fd=write_conn.fd), 
                            buff_ptr,
                            UInt(bytes_read)
                        ).user_data(write_conn.to_int())
            
            # Handle write completion
            elif conn.type == WRITE:
                print("Write completion: fd=", conn.fd)
                
                # Extract buffer ID
                buffer_id = conn.bid
                # Parse buffer ID to get group and index
                (grp, idx) = BufferRing.parse_buffer_id(buffer_id)
                
                # Update buffer in the ring (this marks it as available again)
                buffer_addr = UInt64(Int(buffer_memory.get_buffer_pointer(idx)))
                buffer_memory.buffer_ring.update_entry(
                    Int(idx), 
                    IoUringBufferRingEntry(buffer_addr, UInt32(MAX_MESSAGE_LEN))
                )
                
                # Post a new read for the connection
                sq = ring.sq()
                if sq:
                    read_conn = ConnInfo(fd=conn.fd, type=READ)
                    _ = Read[type=SQE64, origin=__origin_of(sq)](
                        sq.__next__(), 
                        Fd(unsafe_fd=conn.fd), 
                        UnsafePointer[BYTE](), # Ring buffer will be selected by the kernel
                        UInt(MAX_MESSAGE_LEN)
                    ).user_data(read_conn.to_int()).sqe_flags(IoUringSqeFlags.BUFFER_SELECT).buf_group(buf_grp_id)
