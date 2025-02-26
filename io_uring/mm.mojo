from .cq import Cq
from .params import Entries
from .utils import _add_with_overflow
from mojix.ctypes import c_void
from mojix.utils import StaticMutableOrigin
from mojix.io_uring import (
    Sqe,
    SQE,
    Cqe,
    CQE,
    IoUringParams,
    IoUringSetupFlags,
    IoUringRegisterOp, 
    RegisterArg,
    io_uring_register
)
from mojix.errno import Errno
from mojix.fd import FileDescriptor, IoUringFileDescriptor
from mojix.mm import (
    mmap,
    mmap_anonymous,
    munmap,
    madvise,
    ProtFlags,
    MapFlags,
    Advice,
)
from sys.info import alignof, sizeof
from memory import UnsafePointer
from linux_raw.utils import SafeSlice


struct Region(Movable):
    var ptr: UnsafePointer[c_void]
    var len: UInt

    # ===------------------------------------------------------------------=== #
    # Life cycle methods
    # ===------------------------------------------------------------------=== #

    @always_inline
    fn __init__[
        Fd: FileDescriptor
    ](out self, *, fd: Fd, offset: UInt64, len: UInt) raises:
        self.ptr = mmap(
            unsafe_ptr=UnsafePointer[c_void](),
            len=len,
            prot=ProtFlags.READ | ProtFlags.WRITE,
            flags=MapFlags.SHARED | MapFlags.POPULATE,
            fd=fd,
            offset=offset,
        )
        debug_assert(self.ptr, "null pointer")
        self.len = len

    @always_inline
    fn __init__(out self, *, len: UInt, flags: MapFlags) raises:
        self.ptr = mmap_anonymous(
            unsafe_ptr=UnsafePointer[c_void](),
            len=len,
            prot=ProtFlags.READ | ProtFlags.WRITE,
            flags=MapFlags.SHARED | MapFlags.POPULATE | flags,
        )
        debug_assert(self.ptr, "null pointer")
        self.len = len

    @always_inline
    fn __del__(owned self):
        try:
            munmap(unsafe_ptr=self.ptr, len=self.len)
        except:
            pass

    @always_inline
    fn __moveinit__(out self, owned existing: Self):
        """Moves data of an existing Region into a new one.

        Args:
            existing: The existing Region.
        """
        self.ptr = existing.ptr
        self.len = existing.len

    # ===-------------------------------------------------------------------===#
    # Methods
    # ===-------------------------------------------------------------------===#

    @always_inline
    fn dontfork(self) raises:
        madvise(unsafe_ptr=self.ptr, len=self.len, advice=Advice.DONTFORK)

    @always_inline
    fn unsafe_ptr[
        T: AnyType
    ](self, *, offset: UInt32, count: UInt32) raises -> UnsafePointer[T]:
        constrained[alignof[T]() > 0]()
        constrained[sizeof[c_void]() == 1]()

        len = _add_with_overflow(offset, count * sizeof[T]())
        if len[1]:
            raise "len overflow"
        if len[0] > self.len:
            raise "offset is out of bounds"
        ptr = self.ptr.offset(Int(offset))
        if Int(ptr) & (alignof[T]() - 1):
            raise "region is not properly aligned"
        return ptr.bitcast[T]()

    @always_inline
    fn addr(self) -> UInt64:
        return Int(self.ptr)


struct MemoryMapping[sqe: SQE, cqe: CQE](Movable):
    var sqes_mem: Region
    var sq_cq_mem: Region

    # ===------------------------------------------------------------------=== #
    # Life cycle methods
    # ===------------------------------------------------------------------=== #

    @always_inline
    fn __init__(out self, *, owned sqes_mem: Region, owned sq_cq_mem: Region):
        self.sqes_mem = sqes_mem^
        self.sq_cq_mem = sq_cq_mem^

    fn __init__(
        out self, sq_entries: UInt32, mut params: IoUringParams
    ) raises:
        entries = Entries(sq_entries=sq_entries, params=params)
        # FIXME: Get the actual page size value at runtime.
        alias page_size = 4096
        sqes_size = entries.sq_entries * sqe.size
        sq_array_size = (
            0 if params.flags
            & IoUringSetupFlags.NO_SQARRAY else entries.sq_entries
            * sizeof[UInt32]()
        )
        sq_cq_size = (
            cqe.rings_size + entries.cq_entries * cqe.size + sq_array_size
        )

        alias HUGE_PAGE_SIZE = 1 << 21
        if sqes_size > HUGE_PAGE_SIZE or sq_cq_size > HUGE_PAGE_SIZE:
            raise String(Errno.ENOMEM)

        flags = MapFlags()
        if sqes_size <= page_size:
            sqes_size = page_size
        else:
            sqes_size = HUGE_PAGE_SIZE
            flags |= MapFlags.HUGETLB | MapFlags.HUGE_2MB

        self.sqes_mem = Region(
            len=UInt(sqes_size.cast[DType.index]().value), flags=flags
        )

        flags = MapFlags()
        if sq_cq_size <= page_size:
            sq_cq_size = page_size
        else:
            sq_cq_size = HUGE_PAGE_SIZE
            flags |= MapFlags.HUGETLB | MapFlags.HUGE_2MB

        self.sq_cq_mem = Region(
            len=UInt(sq_cq_size.cast[DType.index]().value), flags=flags
        )

        params.cq_off.user_addr = self.sq_cq_mem.addr()
        params.sq_off.user_addr = self.sqes_mem.addr()

    @always_inline
    fn __moveinit__(out self, owned existing: Self):
        """Moves data of an existing MemoryMapping into a new one.

        Args:
            existing: The existing MemoryMapping.
        """
        self.sqes_mem = existing.sqes_mem^
        self.sq_cq_mem = existing.sq_cq_mem^

    # ===-------------------------------------------------------------------===#
    # Methods
    # ===-------------------------------------------------------------------===#

    @always_inline
    fn dontfork(self) raises:
        self.sqes_mem.dontfork()
        self.sq_cq_mem.dontfork()


@value
struct IoUringPbufRing:
    """Ring mapped buffer structure for io_uring.
    
    This is used to register a buffer ring that can be shared between the
    application and the kernel, providing zero-copy operation for
    networking operations.
    """
    var addr: UInt64    # Buffer ring address
    var len: UInt32     # Length of the ring
    var buf_ring: UInt16  # Buffer ring index
    var buf_grp: UInt16  # Buffer group ID
    var pad: UInt64     # Padding for alignment
    
    @always_inline
    fn __init__(out self):
        """Initialize an empty pbuf ring."""
        self.addr = 0
        self.len = 0
        self.buf_ring = 0
        self.buf_grp = 0
        self.pad = 0
    
    @always_inline
    fn __init__(out self, addr: UInt64, len: UInt32, buf_ring: UInt16, buf_grp: UInt16):
        """Initialize a pbuf ring with given parameters.
        
        Args:
            addr: Buffer ring address.
            len: Length of the ring.
            buf_ring: Buffer ring index.
            buf_grp: Buffer group ID.
        """
        self.addr = addr
        self.len = len
        self.buf_ring = buf_ring
        self.buf_grp = buf_grp
        self.pad = 0
    
    @staticmethod
    fn register_pbuf_ring[
        Fd: IoUringFileDescriptor
    ](pbuf_slice: SafeSlice[IoUringPbufRing], fd: Fd) raises -> UInt32:
        """Register a pbuf ring with the io_uring instance.
        
        Args:
            pbuf_slice: A slice of pbuf rings to register.
            fd: The file descriptor returned by `io_uring_setup`.

        Returns:
            The number of registered pbuf rings.
            
        Raises:
            `Errno` if the syscall returned an error.
        """
        _ = io_uring_register[Fd](
            fd=fd,
            arg=RegisterArg[StaticMutableOrigin](
                opcode=IoUringRegisterOp.REGISTER_PBUF_RING,
                arg_unsafe_ptr=UnsafePointer(pbuf_slice.ref_unsafe_ptr()).bitcast[c_void](),
                nr_args=UInt32(pbuf_slice.ref_size()),
            ),
        )
        
        return UInt32(pbuf_slice.ref_size())
    
    @staticmethod
    fn unregister_pbuf_ring[
        Fd: IoUringFileDescriptor
    ](fd: Fd) raises:
        """Unregister all previously registered pbuf rings.
        
        Args:
            fd: The file descriptor returned by `io_uring_setup`.

        Raises:
            `Errno` if the syscall returned an error.
        """
        _ = io_uring_register[Fd](
            fd=fd,
            arg=RegisterArg[StaticMutableOrigin](
                opcode=IoUringRegisterOp.UNREGISTER_PBUF_RING,
                arg_unsafe_ptr=UnsafePointer[c_void](),
                nr_args=0,
            ),
        )
