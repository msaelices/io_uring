from mojix.fd import OwnedFd
from mojix.io_uring import SQE64
from io_uring import IoUring, BufferRing, IoUringBufferRingEntry
from memory import UnsafePointer
import sys


fn test_buffer_ring_create() raises:
    """Test that we can create a buffer ring."""
    var buf_grp = UInt16(1)
    var ring_size = 32
    var buf_ring = BufferRing(ring_size, buf_grp)
    
    # Add a buffer
    var buffer_data = UInt64(123456)  # Example address, not a real buffer 
    buf_ring.add_buffer(0, buffer_data, UInt32(4096))
    
    # Retrieve it
    var entry = buf_ring.get_entry(0)
    if entry.addr != buffer_data:
        raise "Buffer not stored correctly"
    if entry.len != 4096:
        raise "Length not stored correctly"


fn test_buffer_id_parsing() raises:
    """Test buffer ID encoding/decoding."""
    var grp = UInt16(5)
    var idx = UInt16(123)
    
    # Create a buffer ID
    var bid = BufferRing.make_buffer_id(grp, idx)
    
    # Parse it back
    var result = BufferRing.parse_buffer_id(bid)
    var parsed_grp = result[0]
    var parsed_idx = result[1]
    
    if parsed_grp != grp:
        raise "Group ID parsing failed"
    if parsed_idx != idx:
        raise "Buffer index parsing failed"
    
