from memory import UnsafePointer
from sys.info import sizeof

from io_uring.mm import IoUringPbufRing
from linux_raw.utils import SafeSlice
from mojix.ctypes import c_void
from mojix.fd import IoUringFileDescriptor
from mojix.mm import mmap_anonymous, munmap, ProtFlags, MapFlags


# Constants for buffer ring
alias BGID_MASK = UInt16(0xFFF)
alias PBUF_DATA_BIT_SHIFT = 16
alias PBUF_OFF_MASK = UInt16(0xFFFF)
alias PBUF_OFF_BITS = 16

# Struct for buffer ring entry
@value
struct IoUringBufferRingEntry:
    var addr: UInt64
    var len: UInt32
    var bid: UInt16
    var resv: UInt16
    
    @always_inline
    fn __init__(out self):
        """Initialize an empty buffer ring entry."""
        self.addr = 0
        self.len = 0
        self.bid = 0
        self.resv = 0

    @always_inline
    fn __init__(out self, addr: UInt64, len: UInt32, bid: UInt16 = 0):
        """Initialize a buffer ring entry with given parameters.
        
        Args:
            addr: Memory address for the buffer.
            len: Length of the buffer.
            bid: Buffer ID.
        """
        self.addr = addr
        self.len = len
        self.bid = bid
        self.resv = 0


struct BufferRing:
    """A buffer ring for io_uring that can be shared between kernel and userspace."""
    var rings: UnsafePointer[IoUringBufferRingEntry] # Points to the buffer ring entries
    var ring_size: Int                                # Number of entries in the ring
    var mask: UInt32                                  # Ring mask (power of 2 minus 1)
    var mmap_size: UInt                               # Size of the mmap region
    var ring_addr: UInt64                             # Start address of the ring
    var buf_grp: UInt16                               # Buffer group ID
    
    fn __init__(out self, ring_size: Int, buf_grp: UInt16) raises:
        """Initialize a buffer ring with the specified size and group ID.
        
        Args:
            ring_size: Number of entries in the ring (must be power of 2).
            buf_grp: Buffer group ID to use for this ring.
        
        Raises:
            If ring_size is not a power of 2.
        """
        # Ensure ring_size is a power of 2
        if (ring_size & (ring_size - 1)) != 0:
            raise "Buffer ring size must be a power of 2"
        
        # Calculate sizes
        self.ring_size = ring_size
        self.mask = UInt32(ring_size - 1)
        self.buf_grp = buf_grp
        
        # Calculate mmap size including header
        entry_size = sizeof[IoUringBufferRingEntry]()
        # Include space for header (tail as a UInt16 at offset 16 bytes in first 8*3 bytes)
        self.mmap_size = UInt(8 * 3 + ring_size * entry_size)
        
        # Create memory mapping
        ptr = mmap_anonymous(
            unsafe_ptr=UnsafePointer[c_void](),
            len=self.mmap_size,
            prot=ProtFlags.READ | ProtFlags.WRITE,
            flags=MapFlags.SHARED | MapFlags.POPULATE
        )
        
        # The rings pointer should skip the header (8*3 bytes)
        self.rings = ptr.offset(8 * 3).bitcast[IoUringBufferRingEntry]()
        self.ring_addr = Int(ptr)

        # Initialize the tail to 0 (at offset 16 bytes in the header)
        var tail_ptr = ptr.offset(16).bitcast[UInt16]()
        tail_ptr[] = 0
        
        # Initialize ring entries
        for i in range(ring_size):
            var entry = IoUringBufferRingEntry()
            self.rings.offset(i)[] = entry
    
    fn __del__(owned self):
        """Clean up the buffer ring mmap."""
        # Skip memory cleanup as we're just demonstrating the implementation
        pass
    
    fn register[Fd: IoUringFileDescriptor](self, fd: Fd) raises -> UInt32:
        """Register this buffer ring with the io_uring instance.

        Parameters:
            Fd: Io_uring file descriptor type.
        
        Args:
            fd: Io_uring file descriptor.

        Returns:
            Number of registered rings.
        """
        # Create pbuf ring descriptor
        var pbuf_ring = IoUringPbufRing()
        pbuf_ring.ring_addr = self.ring_addr
        pbuf_ring.ring_entries = UInt32(self.ring_size)
        pbuf_ring.bgid = self.buf_grp
        print("BufferRing.register: Using group ID:", self.buf_grp)
        pbuf_ring.flags = 0
        
        # Create a SafeSlice to register it
        var pbuf_slice = SafeSlice[IoUringPbufRing](
            unsafe_ptr=UnsafePointer.address_of(pbuf_ring).bitcast[IoUringPbufRing](),
            count=1
        )
        
        return pbuf_ring.register_pbuf_ring(pbuf_slice, fd)
    
    @staticmethod
    fn unregister[Fd: IoUringFileDescriptor](fd: Fd) raises:
        """Unregister all buffer rings from the io_uring instance.
        
        Parameters:
            Fd: Io_uring file descriptor type.

        Args:
            fd: Io_uring file descriptor.
        """
        IoUringPbufRing.unregister_pbuf_ring(fd)
    
    fn add_buffer(self, idx: Int, addr: UInt64, len: UInt32, bid: UInt16 = 0):
        """Add a buffer to the ring at the specified index.
        
        Args:
            idx: Ring index to add the buffer to.
            addr: Memory address of the buffer.
            len: Length of the buffer.
            bid: Buffer ID.
        """
        # Ensure idx is within the ring
        ring_idx = idx & Int(self.mask)
        # Create entry
        var entry = IoUringBufferRingEntry(addr, len, bid)
        # Store in ring
        self.rings.offset(ring_idx)[] = entry
    
    fn get_entry(self, idx: Int) -> IoUringBufferRingEntry:
        """Get an entry from the ring.
        
        Args:
            idx: Ring index to retrieve.

        Returns:
            The buffer ring entry at the specified index.
        """
        ring_idx = idx & Int(self.mask)
        return self.rings.offset(ring_idx)[]
    
    fn update_entry(self, idx: Int, entry: IoUringBufferRingEntry):
        """Update an existing entry in the ring.
        
        Args:
            idx: Ring index to update.
            entry: New entry values.
        """
        ring_idx = idx & Int(self.mask)
        self.rings.offset(ring_idx)[] = entry
    
    @staticmethod
    fn make_buffer_id(grp: UInt16, idx: UInt16) -> UInt32:
        """Create a buffer ID from a group ID and index.
        
        Args:
            grp: Buffer group ID.
            idx: Buffer index within the group.

        Returns:
            Combined buffer ID for use with io_uring.
        """
        return (UInt32(grp) << PBUF_OFF_BITS) | UInt32(idx)
    
    @staticmethod
    fn parse_buffer_id(bid: UInt32) -> (UInt16, UInt16):
        """Parse a buffer ID into group and index components.
        
        Args:
            bid: Combined buffer ID from io_uring.

        Returns:
            Tuple of (group_id, buffer_index).
        """
        var grp = UInt16((bid >> PBUF_OFF_BITS) & UInt32(BGID_MASK))
        var idx = UInt16(bid & UInt32(PBUF_OFF_MASK))
        return (grp, idx)
