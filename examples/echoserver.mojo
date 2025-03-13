import sys
from collections import InlineArray
from memory import UnsafePointer

from mojix.fd import Fd
from mojix.net.socket import socket, bind, listen
from mojix.net.types import AddrFamily, SocketType, SocketAddrV4
from mojix.ctypes import c_void
from mojix.io_uring import IoUringOp, IoUringSqeFlags
from io_uring import IoUring
from io_uring.buf import BufRing
from io_uring.op import Accept, Read, Write

alias BYTE = Int8
alias BACKLOG = 512
alias MAX_MESSAGE_LEN = 2048
alias BUFFERS_COUNT = 16  # Must be power of 2
# Number of entries in the submission queue
alias SQ_ENTRIES = 512

alias ACCEPT = 0
alias READ = 1
alias WRITE = 2


@value
@register_passable("trivial")
struct ConnInfo:
    var fd: Int32
    var type: UInt16
    var bid: UInt16  # Buffer ID

    fn __init__(out self, fd: Int32, type: UInt16, bid: UInt16 = 0):
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
            bid=UInt16(value & 0xFFFF)  # Use lower 16 bits for buffer ID
        )


fn main() raises:
    """Run an echo server using io_uring with ring mapped buffers."""
    args = sys.argv()
    port = Int(args[1]) if len(args) > 1 else 8080
    
    # Initialize io_uring instance
    ring = IoUring(sq_entries=SQ_ENTRIES)

    # Create buffer ring for efficient memory management
    print("Initializing buffer ring with", BUFFERS_COUNT, "entries of size", MAX_MESSAGE_LEN)
    # Use buffer group ID 0 as that's what kernel expects by default
    var buf_ring = ring.create_buf_ring(
        bgid=0,  # Buffer group ID (must be consistent with Recv operation)
        entries=BUFFERS_COUNT,
        entry_size=MAX_MESSAGE_LEN
    )
    
    # Setup listener socket with error handling
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

        if submitted < 0:
            print("Error: No submissions", submitted)
            break
        
        # Process completions
        for cqe in ring.cq(wait_nr=0):
            res = cqe.res
            user_data = cqe.user_data
            flags = cqe.flags
            
            conn = ConnInfo.from_int(user_data)
            
            if res < 0:
                print("Error:", res, "on operation type:", conn.type, "fd:", conn.fd)
                continue
            
            # Handle accept completion
            if conn.type == ACCEPT:
                # New connection
                client_fd = Fd(unsafe_fd=res)
                active_connections += 1
                print("New connection (active:", active_connections, ")")

                # Set up a read using IOSQE_BUFFER_SELECT to have kernel pick a buffer
                _submit_read_with_buffer_select(client_fd.unsafe_fd(), ring, buf_ring)
                
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
                    print("Connection closed (active:", active_connections, ")")
                else:
                    # Get buffer handle from completion flags
                    bytes_read = Int(res)
                    var buf_ring_ptr = buf_ring[]
                    
                    # Extract buffer index from completion flags using the static method in BufRing
                    var buffer_idx = BufRing.flags_to_index(flags)
                    print("Read completion (bytes:", bytes_read, ", buffer_idx:", buffer_idx, ")")
                    
                    # The kernel gave us ownership of a buffer identified by buffer_idx
                    # Get a buffer handle to safely use it and ensure proper recycling
                    var buffer = buf_ring_ptr.unsafe_buf(index=buffer_idx, len=UInt32(bytes_read))
                    
                    # Store the buffer data in write state
                    _submit_write_with_buffer(conn.fd, buffer.buf_ptr, bytes_read, ring)
                    
            # Handle write completion
            elif conn.type == WRITE:
                print("Write completion (fd:", conn.fd, ")")
                
                # Post a new read for the connection with buffer select
                _submit_read_with_buffer_select(conn.fd, ring, buf_ring)

    # Clean up
    ring.unsafe_delete_buf_ring(buf_ring^)


# Helper functions

fn _submit_write_with_buffer(fd: Int32, buf_ptr: UnsafePointer[c_void], bytes_read: Int, mut ring: IoUring) raises:
    """Handle read completion by submitting a write with the provided buffer pointer.
    The buffer will be recycled when the Buf object goes out of scope in the caller."""
    
    sq = ring.sq()
    if sq:
        write_conn = ConnInfo(fd=fd, type=WRITE)
        print("Setting up write with fd:", write_conn.fd)
        
        _ = Write(
            sq.__next__(), 
            Fd(unsafe_fd=write_conn.fd), 
            buf_ptr,
            UInt(bytes_read)
        ).user_data(write_conn.to_int())


fn _submit_read_with_buffer_select(fd: Int32, mut ring: IoUring, mut buf_ring: BufRing) raises:
    """Submit a read operation with BUFFER_SELECT flag to have the kernel select a buffer.
    This is the proper way to use buffer rings - let the kernel pick a buffer from the
    ring rather than selecting ourselves."""
    
    sq = ring.sq()
    if sq:
        read_conn = ConnInfo(fd=fd, type=READ)
        
        print("Setting up read with buffer select for fd:", fd)
        
        # Setup a Read operation with proper buffer select flags
        var client_fd = Fd(unsafe_fd=fd)
        var buf_ring_ptr = buf_ring[]
        var buffer_ptr = buf_ring_ptr.unsafe_buf(index=0, len=UInt32(MAX_MESSAGE_LEN)).buf_ptr
        var sqe = sq.__next__()
        sqe.flags |= IoUringSqeFlags.BUFFER_SELECT
        _ = Read(
            sq.__next__(),
            client_fd,
            buffer_ptr,
            UInt(MAX_MESSAGE_LEN)
        ).user_data(read_conn.to_int())

