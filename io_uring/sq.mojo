from .mm import Region
from .op import _nop_data
from .modes import PollingMode, SQPOLL
from .utils import AtomicOrdering, _atomic_load, _atomic_store
from mojix.io_uring import (
    Sqe,
    SQE,
    SQE64,
    SQE128,
    IoUringParams,
    IoUringSetupFlags,
)


struct Sq[type: SQE, polling: PollingMode](Sized, Boolable):
    var _head: UnsafePointer[UInt32]
    var _tail: UnsafePointer[UInt32]
    var _flags: UnsafePointer[UInt32]
    var dropped: UnsafePointer[UInt32]

    var array: UnsafePointer[UInt32]
    var sqes: UnsafePointer[Sqe[type]]

    var sqe_head: UInt32
    var sqe_tail: UInt32

    var ring_mask: UInt32
    var ring_entries: UInt32

    fn __init__(
        inout self,
        params: IoUringParams,
        *,
        sq_cq_mem: Region,
        sqes_mem: Region,
    ) raises:
        constrained[
            type is SQE64 or type is SQE128,
            "SQE must be equal to SQE64 or SQE128",
        ]()
        constrained[sizeof[Sqe[type]]() == type.size]()
        constrained[alignof[Sqe[type]]() == type.align]()

        self._head = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.head, count=1
        )
        self._tail = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.tail, count=1
        )
        self._flags = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.flags, count=1
        )
        self.dropped = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.dropped, count=1
        )
        self.ring_mask = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.ring_mask, count=1
        )[]
        self.ring_entries = sq_cq_mem.unsafe_ptr[UInt32](
            offset=params.sq_off.ring_entries, count=1
        )[]
        # We expect the kernel copies `params.sq_entries` to the UInt32
        # pointed to by `params.sq_off.ring_entries`.
        # [Linux]: https://github.com/torvalds/linux/blob/v6.7/io_uring/io_uring.c#L38.
        if self.ring_entries != params.sq_entries or self.ring_entries == 0:
            raise "invalid sq ring_entries value"
        if self.ring_mask != self.ring_entries - 1:
            raise "invalid sq ring_mask value"

        if params.flags & IoUringSetupFlags.NO_SQARRAY:
            self.array = UnsafePointer[UInt32]()
        else:
            self.array = sq_cq_mem.unsafe_ptr[UInt32](
                offset=params.sq_off.array, count=self.ring_entries
            )
            # Directly map `sq` slots to `sqes`.
            for i in range(self.ring_entries):
                self.array[i] = i

        self.sqes = sqes_mem.unsafe_ptr[Sqe[type]](
            offset=0, count=self.ring_entries
        )
        self.sqe_head = self._head[]
        self.sqe_tail = self._tail[]

    # ===-------------------------------------------------------------------===#
    # Trait implementations
    # ===-------------------------------------------------------------------===#

    @always_inline
    fn __len__(self) -> Int:
        """Returns the number of available sq entries.

        Returns:
            The number of available sq entries.
        """
        return (
            (self.ring_entries - (self.sqe_tail - self.sqe_head))
            .cast[DType.index]()
            .value
        )

    @always_inline
    fn __bool__(self) -> Bool:
        """Checks whether the sq has any available entries or not.

        Returns:
            `False` if the sq is full, `True` if there is at least one available
            entry.
        """
        return self.sqe_tail - self.sqe_head != self.ring_entries

    # ===-------------------------------------------------------------------===#
    # Methods
    # ===-------------------------------------------------------------------===#

    @always_inline
    fn sync_head(inout self):
        self.sqe_head = self.head[AtomicOrdering.ACQUIRE]()

    @always_inline
    fn head[ordering: AtomicOrdering](self) -> UInt32:
        @parameter
        if polling is SQPOLL:
            return _atomic_load[ordering](self._head)
        else:
            return self._head[]

    @always_inline
    fn sync_tail(inout self):
        @parameter
        if polling is SQPOLL:
            _atomic_store(self._tail, self.sqe_tail)
        else:
            self._tail[] = self.sqe_tail

    @always_inline
    fn flush(inout self) -> UInt32:
        if self.sqe_head != self.sqe_tail:
            self.sqe_head = self.sqe_tail
            # Ensure that the kernel can actually see the sqe updates
            # when it sees the tail update.
            self.sync_tail()

        # `self.head()` load needs to be atomic when we're in SQPOLL mode
        # since head is written concurrently by the kernel, but it
        # doesn't need to be `AtomicOrdering.ACQUIRE`, since the kernel
        # doesn't store to the submission queue. It advances head just to
        # indicate that it's finished reading the submission queue entries
        # so they're available for us to write to.
        return self.sqe_tail - self.head[AtomicOrdering.RELAXED]()

    @always_inline
    fn flags(self) -> UInt32:
        return _atomic_load[AtomicOrdering.RELAXED](self._flags)


@register_passable
struct SqRef[sq_lifetime: MutableLifetime, type: SQE, polling: PollingMode]:
    var sq: Reference[Sq[type, polling], sq_lifetime]

    @always_inline
    fn __init__(inout self, ref [sq_lifetime]sq: Sq[type, polling]):
        self.sq = sq

    @always_inline
    fn __iter__(owned self) -> Self:
        return self^

    @always_inline
    fn __len__(self) -> Int:
        """Returns the number of available sq entries.

        Returns:
            The number of available sq entries.
        """
        return len(self.sq[])

    @always_inline
    fn __next__(
        inout self,
    ) -> ref [__lifetime_of(self)] Sqe[type]:
        var ptr = self.sq[].sqes.offset(
            self.sq[].sqe_tail & self.sq[].ring_mask
        )
        self.sq[].sqe_tail += 1
        return _nop_data(ptr[])
