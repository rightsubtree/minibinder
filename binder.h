#ifndef _UAPI_LINUX_BINDER_H
#define _UAPI_LINUX_BINDER_H

// 假设都运行在64位设备上，本代码没有在32位设备上测试过
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;

struct binder_write_read {
    binder_size_t       write_size;
    binder_size_t       write_consumed;
    binder_uintptr_t    write_buffer;
    binder_size_t       read_size;
    binder_size_t       read_consumed;
    binder_uintptr_t    read_buffer;
};

struct binder_transaction_data {
    __u32       code;
    __u32       flags;
    binder_size_t   data_size;
    binder_size_t   offsets_size;
    union {
        struct {
            binder_uintptr_t    buffer;
            binder_uintptr_t    offsets;
        } ptr;
        __u8    buf[8];
    } data;
};

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)

enum binder_driver_command_protocol {
    BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
    BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
    BC_FREE_BUFFER = _IOW('c', 3, binder_uintptr_t),
};

enum binder_driver_return_protocol {
    BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
    BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
    BR_TRANSACTION_COMPLETE = _IO('r', 6),
};

#endif /* _UAPI_LINUX_BINDER_H */