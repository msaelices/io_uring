alias IORING_SETUP_IOPOLL = 1
alias IORING_SETUP_SQPOLL = 2
alias IORING_SETUP_SQ_AFF = 4
alias IORING_SETUP_CQSIZE = 8
alias IORING_SETUP_CLAMP = 16
alias IORING_SETUP_ATTACH_WQ = 32
alias IORING_SETUP_R_DISABLED = 64
alias IORING_SETUP_SUBMIT_ALL = 128
alias IORING_SETUP_COOP_TASKRUN = 256
alias IORING_SETUP_TASKRUN_FLAG = 512
alias IORING_SETUP_SQE128 = 1024
alias IORING_SETUP_CQE32 = 2048
alias IORING_SETUP_SINGLE_ISSUER = 4096
alias IORING_SETUP_DEFER_TASKRUN = 8192
alias IORING_SETUP_NO_MMAP = 16384
alias IORING_SETUP_REGISTERED_FD_ONLY = 32768
alias IORING_SETUP_NO_SQARRAY = 65536
alias IORING_URING_CMD_FIXED = 1
alias IORING_URING_CMD_MASK = 1
alias IORING_FSYNC_DATASYNC = 1

alias IORING_POLL_ADD_MULTI = 1
alias IORING_POLL_UPDATE_EVENTS = 2
alias IORING_POLL_UPDATE_USER_DATA = 4
alias IORING_POLL_ADD_LEVEL = 8
alias IORING_ASYNC_CANCEL_ALL = 1
alias IORING_ASYNC_CANCEL_FD = 2
alias IORING_ASYNC_CANCEL_ANY = 4
alias IORING_ASYNC_CANCEL_FD_FIXED = 8
alias IORING_ASYNC_CANCEL_USERDATA = 16
alias IORING_ASYNC_CANCEL_OP = 32
alias IORING_RECVSEND_POLL_FIRST = 1
alias IORING_RECV_MULTISHOT = 2
alias IORING_RECVSEND_FIXED_BUF = 4
alias IORING_SEND_ZC_REPORT_USAGE = 8
alias IORING_NOTIF_USAGE_ZC_COPIED = 2147483648
alias IORING_ACCEPT_MULTISHOT = 1
alias IORING_MSG_RING_CQE_SKIP = 1
alias IORING_MSG_RING_FLAGS_PASS = 2
alias IORING_CQE_F_BUFFER = 1
alias IORING_CQE_F_MORE = 2
alias IORING_CQE_F_SOCK_NONEMPTY = 4
alias IORING_CQE_F_NOTIF = 8

alias IORING_OFF_SQ_RING = 0
alias IORING_OFF_CQ_RING = 134217728
alias IORING_OFF_SQES = 268435456
alias IORING_SQ_NEED_WAKEUP = 1
alias IORING_SQ_CQ_OVERFLOW = 2
alias IORING_SQ_TASKRUN = 4
alias IORING_CQ_EVENTFD_DISABLED = 1
alias IORING_ENTER_GETEVENTS = 1
alias IORING_ENTER_SQ_WAKEUP = 2
alias IORING_ENTER_SQ_WAIT = 4
alias IORING_ENTER_EXT_ARG = 8
alias IORING_ENTER_REGISTERED_RING = 16

alias IORING_FEAT_SINGLE_MMAP = 1
alias IORING_FEAT_NODROP = 2
alias IORING_FEAT_SUBMIT_STABLE = 4
alias IORING_FEAT_RW_CUR_POS = 8
alias IORING_FEAT_CUR_PERSONALITY = 16
alias IORING_FEAT_FAST_POLL = 32
alias IORING_FEAT_POLL_32BITS = 64
alias IORING_FEAT_SQPOLL_NONFIXED = 128
alias IORING_FEAT_EXT_ARG = 256
alias IORING_FEAT_NATIVE_WORKERS = 512
alias IORING_FEAT_RSRC_TAGS = 1024
alias IORING_FEAT_CQE_SKIP = 2048
alias IORING_FEAT_LINKED_FILE = 4096
alias IORING_FEAT_REG_REG_RING = 8192

alias IORING_REGISTER_BUFFERS = 0
alias IORING_UNREGISTER_BUFFERS = 1
alias IORING_REGISTER_FILES = 2
alias IORING_UNREGISTER_FILES = 3
alias IORING_REGISTER_EVENTFD = 4
alias IORING_UNREGISTER_EVENTFD = 5
alias IORING_REGISTER_FILES_UPDATE = 6
alias IORING_REGISTER_EVENTFD_ASYNC = 7
alias IORING_REGISTER_PROBE = 8
alias IORING_REGISTER_PERSONALITY = 9
alias IORING_UNREGISTER_PERSONALITY = 10
alias IORING_REGISTER_RESTRICTIONS = 11
alias IORING_REGISTER_ENABLE_RINGS = 12
alias IORING_REGISTER_FILES2 = 13
alias IORING_REGISTER_FILES_UPDATE2 = 14
alias IORING_REGISTER_BUFFERS2 = 15
alias IORING_REGISTER_BUFFERS_UPDATE = 16
alias IORING_REGISTER_IOWQ_AFF = 17
alias IORING_UNREGISTER_IOWQ_AFF = 18
alias IORING_REGISTER_IOWQ_MAX_WORKERS = 19
alias IORING_REGISTER_RING_FDS = 20
alias IORING_UNREGISTER_RING_FDS = 21
alias IORING_REGISTER_PBUF_RING = 22
alias IORING_UNREGISTER_PBUF_RING = 23
alias IORING_REGISTER_SYNC_CANCEL = 24
alias IORING_REGISTER_FILE_ALLOC_RANGE = 25
alias IORING_REGISTER_LAST = 26
alias IORING_REGISTER_USE_REGISTERED_RING = 2147483648

alias IOSQE_FIXED_FILE_BIT = 0
alias IOSQE_IO_DRAIN_BIT = 1
alias IOSQE_IO_LINK_BIT = 2
alias IOSQE_IO_HARDLINK_BIT = 3
alias IOSQE_ASYNC_BIT = 4
alias IOSQE_BUFFER_SELECT_BIT = 5
alias IOSQE_CQE_SKIP_SUCCESS_BIT = 6

alias IORING_OP_NOP = 0
alias IORING_OP_READV = 1
alias IORING_OP_WRITEV = 2
alias IORING_OP_FSYNC = 3
alias IORING_OP_READ_FIXED = 4
alias IORING_OP_WRITE_FIXED = 5
alias IORING_OP_POLL_ADD = 6
alias IORING_OP_POLL_REMOVE = 7
alias IORING_OP_SYNC_FILE_RANGE = 8
alias IORING_OP_SENDMSG = 9
alias IORING_OP_RECVMSG = 10
alias IORING_OP_TIMEOUT = 11
alias IORING_OP_TIMEOUT_REMOVE = 12
alias IORING_OP_ACCEPT = 13
alias IORING_OP_ASYNC_CANCEL = 14
alias IORING_OP_LINK_TIMEOUT = 15
alias IORING_OP_CONNECT = 16
alias IORING_OP_FALLOCATE = 17
alias IORING_OP_OPENAT = 18
alias IORING_OP_CLOSE = 19
alias IORING_OP_FILES_UPDATE = 20
alias IORING_OP_STATX = 21
alias IORING_OP_READ = 22
alias IORING_OP_WRITE = 23
alias IORING_OP_FADVISE = 24
alias IORING_OP_MADVISE = 25
alias IORING_OP_SEND = 26
alias IORING_OP_RECV = 27
alias IORING_OP_OPENAT2 = 28
alias IORING_OP_EPOLL_CTL = 29
alias IORING_OP_SPLICE = 30
alias IORING_OP_PROVIDE_BUFFERS = 31
alias IORING_OP_REMOVE_BUFFERS = 32
alias IORING_OP_TEE = 33
alias IORING_OP_SHUTDOWN = 34
alias IORING_OP_RENAMEAT = 35
alias IORING_OP_UNLINKAT = 36
alias IORING_OP_MKDIRAT = 37
alias IORING_OP_SYMLINKAT = 38
alias IORING_OP_LINKAT = 39
alias IORING_OP_MSG_RING = 40
alias IORING_OP_FSETXATTR = 41
alias IORING_OP_SETXATTR = 42
alias IORING_OP_FGETXATTR = 43
alias IORING_OP_GETXATTR = 44
alias IORING_OP_SOCKET = 45
alias IORING_OP_URING_CMD = 46
alias IORING_OP_SEND_ZC = 47
alias IORING_OP_SENDMSG_ZC = 48
alias IORING_OP_LAST = 49

alias IORING_MSG_DATA = 0
alias IORING_MSG_SEND_FD = 1


@value
struct io_sqring_offsets(Defaultable):
    var head: UInt32
    var tail: UInt32
    var ring_mask: UInt32
    var ring_entries: UInt32
    var flags: UInt32
    var dropped: UInt32
    var array: UInt32
    var resv1: UInt32
    var user_addr: UInt64

    @always_inline
    fn __init__(inout self):
        self.head = 0
        self.tail = 0
        self.ring_mask = 0
        self.ring_entries = 0
        self.flags = 0
        self.dropped = 0
        self.array = 0
        self.resv1 = 0
        self.user_addr = 0


@value
struct io_cqring_offsets(Defaultable):
    var head: UInt32
    var tail: UInt32
    var ring_mask: UInt32
    var ring_entries: UInt32
    var overflow: UInt32
    var cqes: UInt32
    var flags: UInt32
    var resv1: UInt32
    var user_addr: UInt64

    @always_inline
    fn __init__(inout self):
        self.head = 0
        self.tail = 0
        self.ring_mask = 0
        self.ring_entries = 0
        self.overflow = 0
        self.cqes = 0
        self.flags = 0
        self.resv1 = 0
        self.user_addr = 0
