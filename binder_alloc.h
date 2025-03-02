#ifndef _LINUX_BINDER_ALLOC_H
#define _LINUX_BINDER_ALLOC_H

#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/rtmutex.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/list_lru.h>

#include "binder.h"

struct binder_buffer {
    struct list_head entry;
    unsigned free;
    struct binder_transaction *transaction;
    // binder_transaction里，如果发现来自用户空间的BC_TRANSACTION ，则会填充binder_buffer的target_node域的值为目标service的binder_node；
    // 后续流程走到 binder_thread_read，处理 BINDER_WORK_TRANSACTION 时，
    // 如果发现target_node不为空，则驱动会将cmd设置为BR_TRANSACTION，[此时运行在service进程内，是service刚开始取到请求数据]
    // 如果发现target_node为空，则设置cmd为BR_REPLY，[此时运行在client进程内，是驱动获得了service端的reply数据]；
    // 简单地说，这个target_node就是为了区别当前是否处于整个流程的前半程；
    // binder_node的核心作用是做引用计数，本例子完全没有考虑这个，所以完全没有binder_node这个结构定义，
    // 但为了实现上述区别，所以这里还是保留了这个域的名字，但类型改成了 struct binder_proc*，本例子中给它赋值为target_proc的binder_proc对象的地址；
    struct binder_proc* target_node;
    size_t data_size;
    size_t offsets_size;
    void __user *user_data;
    int    pid;
};

struct binder_alloc {
    struct vm_area_struct *vma;
    struct mm_struct *vma_vm_mm;
    void __user *buffer;
    struct list_head buffers;  // 为了简化，没有使用红黑树，而是仅仅保存一个list
    struct page **pages;       // 页面物理地址列表；本例子没有使用binder_lru_page结构体，直接使用指向page地址的指针的数组（二级指针）
    size_t buffer_size;
    uint32_t buffer_free;
    int pid;
    char name[32];             // 本例新增的，binder_alloc初始化时，用current->comm来初始化，主要是方便打印日志
};

extern int binder_alloc_mmap_handler(struct binder_alloc *alloc, struct vm_area_struct *vma);
extern void binder_alloc_vma_close(struct binder_alloc *alloc);
extern struct binder_buffer *binder_alloc_new_buf(struct binder_alloc *alloc, size_t data_size, size_t offsets_size, int pid);
extern unsigned long binder_alloc_copy_user_to_buffer(struct binder_alloc *alloc, struct binder_buffer *buffer,
        binder_size_t buffer_offset, const void __user *from, size_t bytes);
extern struct binder_buffer *binder_alloc_prepare_to_free(struct binder_alloc *alloc, uintptr_t user_ptr);
extern void binder_alloc_free_buf(struct binder_alloc *alloc, struct binder_buffer *buffer);


#endif /* _LINUX_BINDER_ALLOC_H */
