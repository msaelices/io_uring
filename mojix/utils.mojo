from bit import byte_swap
from sys.info import alignof, sizeof, is_big_endian
from linux_raw.utils import DTypeArray


alias StaticMutableOrigin = __mlir_attr[
    `#lit.origin.field<`,
    `#lit.static.origin : !lit.origin<1>`,
    `, "__constants__"> : !lit.origin<1>`,
]


@always_inline("nodebug")
fn _aligned_u64[T: AnyType]():
    # [Linux]: https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/types.h#L47.
    constrained[alignof[T]() >= 8]()


@always_inline("nodebug")
fn _size_eq[T: AnyType, I: AnyType]():
    constrained[sizeof[T]() == sizeof[I]()]()


@always_inline("nodebug")
fn _size_eq[T: AnyType, size: Int]():
    constrained[sizeof[T]() == size]()


@always_inline("nodebug")
fn _align_eq[T: AnyType, I: AnyType]():
    constrained[alignof[T]() == alignof[I]()]()


@always_inline("nodebug")
fn _align_eq[T: AnyType, align: Int]():
    constrained[alignof[T]() == align]()


@always_inline("nodebug")
fn _to_be[type: DType, size: Int](value: SIMD[type, size]) -> SIMD[type, size]:
    @parameter
    if is_big_endian():
        return value
    else:
        return byte_swap(value)
