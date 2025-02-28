#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

#include "binder.h"
#include "binder_alloc.h"

#define DEVICE_NAME             "minibinder"
#define CLIENT_PROC_NAME        "client"
#define SERVER_PROC_NAME        "server"
#define FORBIDDEN_MMAP_FLAGS    (VM_WRITE)

// 为了剥离非核心逻辑，下面这些结构体定义中删除了很多不需要的域（当然，应该还能进一步阉割一些，就这样吧，不纠结了）；
// 本例子新增或者改变其数据类型的域，我会特别说明；
struct binder_proc {
    int pid;
    struct binder_alloc alloc;
    struct list_head todo;
    struct binder_thread *main_thread;  // 只关心主线程，故将红黑树存储的threads简化为只保存主线程
    char name[32];                      // 本例新增的，当前进程名一般用current->comm，这个主要用于打印对端进程的名字
};

struct binder_thread {
    struct binder_proc *proc;
};

struct binder_work {
    struct list_head entry;
    enum binder_work_type {
        BINDER_WORK_TRANSACTION = 1,
        BINDER_WORK_TRANSACTION_COMPLETE,
    } type;
};

struct binder_transaction {
    struct binder_work work;
    struct binder_thread *from;
    struct binder_proc *to_proc;
    struct binder_thread *to_thread;
    unsigned need_reply;
    struct binder_buffer *buffer;
    unsigned int code;
    unsigned int flags;
};

// 本例子里不存在servicemanager这个角色，所以需要保存一下server和client两个进程的信息，便于找到对端
static struct binder_proc *proc_client;
static struct binder_proc *proc_server;


// 为了方便大家对照， binder.c 和 binder_alloc.c 里的函数名，几乎都维持原样，部分函数删除了一些非核心逻辑的入参

static void binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
                        struct binder_transaction_data *td, int reply) {

    printk(KERN_DEBUG "%s: binder_transaction() BEGIN { \n", current->comm);

    char* cmd_str = reply ? "BC_REPLY" : "BC_TRANSACTION";
    struct binder_transaction *t;   // 添加到目标进程的todo列表
    struct binder_work *tcomplete;  // 添加到当前进程的todo列表
    // 用最简单的方法找到目标进程
    struct binder_proc *target_proc = (proc == proc_client ? proc_server : proc_client);

    printk(KERN_DEBUG
            "%s --> %s %s data.ptr.buffer=%llx data.ptr.offsets=%llx data_size=%lld offsets_size=%lld \n",
            current->comm, target_proc->name, cmd_str, (u64)td->data.ptr.buffer, (u64)td->data.ptr.offsets,
            (u64)td->data_size, (u64)td->offsets_size);

    t = kzalloc(sizeof(*t), GFP_KERNEL);
    tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);

    // 用发起者（即通过ioctl向内核写入数据的进程）提供的 binder_transaction_data 数据，构造一个 binder_transaction
    t->to_proc = target_proc;
    t->from = thread;
    t->code = td->code;
    // 给binder_transaction分配一个 binder_buffer ，这里binder_alloc_new_buf返回的binder_buffer已经是关联了一页内核page的
    t->buffer = binder_alloc_new_buf(&target_proc->alloc, td->data_size, td->offsets_size, current->tgid);
    if(NULL == t->buffer) {
        pr_err("%s: binder_alloc_new_buf cannot find free binder_buffer for pid %d \n", current->comm, current->tgid);
        return;
    }
    t->buffer->transaction = t;
    t->buffer->data_size = td->data_size;
    t->buffer->offsets_size = td->offsets_size;

    // 如果正在处理BC_TRANSACTION，则填充其buffer的target_node，
    // 后续会根据target_node是否为空决定下一个cmd是BR_TRANSACTION还是BR_REPLY；
    // 这里的逻辑保持与原生binder一致，但target_node的数据类型有差异，详见 binder_buffer 结构体定义里的注释
    if(!reply) {
        t->buffer->target_node = target_proc;
    }

    // 接下来会执行两次 copy_from_user，将 binder_transaction_data 里面指针 data.ptr.buffer 和 data.ptr.offsets 指向的数据
    // 拷贝到内核刚刚分配的 binder_buffer 里面；本质上，这个拷贝实际上就是将原来 binder_transaction_data 里面的“结构化数据”做“序列化”的过程；
    // 而到了对端进程（用户空间进程里），需要做“反序列化”，反序列化时的解析规则是由 data_size 和 offsets_size 决定的，详见用户空间的 binder_parse 函数；

    // binder_transaction_data 的 data.ptr.buffer 中存储了 data_size 个字节的数据，
    // 将它们拷贝到刚刚分配的binder_buffer的第0个offset的位置；
    if (binder_alloc_copy_user_to_buffer( &target_proc->alloc, t->buffer, 0,
                (const void __user *)(uintptr_t)td->data.ptr.buffer, td->data_size )) {
        printk(KERN_DEBUG "%d: got transaction with invalid data ptr \n", proc->pid);
    }

    // binder_transaction_data 的 data.ptr.offsets 其实是一个数组，存储了 offsets_size 个字节的数据
    // （在64位系统，offsets_size = data.ptr.buffer里面obj的个数 * 8 ），
    // 需要将它们拷贝到刚刚分配的binder_buffer的第 ALIGN(td->data_size, sizeof(void *)) 个offset的位置；
    // ALIGN(x, y) 的意思是，将x上对齐到y的整数倍；假如 data_size=9，则64位上 ALIGN(9, 8) 计算后的值是16；
    // ALIGN的主要目的还是为了加速数据读写速度
    if (binder_alloc_copy_user_to_buffer( &target_proc->alloc, t->buffer, ALIGN(td->data_size, sizeof(void *)),
                (const void __user *)(uintptr_t)td->data.ptr.offsets, td->offsets_size )) {
        printk(KERN_DEBUG "%d: got transaction with invalid offsets ptr \n", proc->pid);
    }

    // 将一个 BINDER_WORK_TRANSACTION 添加到 target_proc 的todo列表
    // 所有添加到todo列表的都是一个 binder_work ，所以这里添加的其实是 binder_transaction 的一个子域 t->work 的指针
    // 后续target_proc 执行到 binder_thread_read 收到binder_work后，通过 container_of 宏获得外层的 binder_transaction
    t->work.type = BINDER_WORK_TRANSACTION;
    list_add_tail(&t->work.entry, &target_proc->todo);
    printk(KERN_DEBUG
            "%s: --> %s BINDER_WORK_TRANSACTION (code=%d buffer=%llx data_size=%ld offsets_size=%ld) \n",
            current->comm, target_proc->name, t->code, (u64)t->buffer, t->buffer->data_size, t->buffer->offsets_size);

    // 将一个 BINDER_WORK_TRANSACTION_COMPLETE 添加到源进程的todo列表，会被源进程在执行 binder_thread_read 时获取
    tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
    list_add_tail(&tcomplete->entry, &thread->proc->todo);
    printk(KERN_DEBUG "%s: --> %s BINDER_WORK_TRANSACTION_COMPLETE \n", current->comm, thread->proc->name);

    printk(KERN_DEBUG "%s: binder_transaction()   END } \n", current->comm);
}


static int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
                    binder_uintptr_t write_buffer, size_t size, binder_size_t *consumed) {

    uint32_t cmd;
    void __user *buffer = (void __user *)(uintptr_t)write_buffer;
    void __user *ptr = buffer + *consumed;
    void __user *end = buffer + size;

    // 外层的while循环，是为了处理一个write写两个cmd的情况，
    // 例如server通过一个ioctl写了一个包含 BC_FREE_BUFFER+ BC_REPLY的两个数据
    while (ptr < end) {
        if (get_user(cmd, (uint32_t __user *)ptr)) {
            printk(KERN_DEBUG "%s: binder_thread_write get_user ERROR \n", current->comm);
            return -1;
        }
        ptr += sizeof(uint32_t);

        switch(cmd) {
        case BC_FREE_BUFFER: {
            printk(KERN_DEBUG "%s: binder_thread_write cmd=BC_FREE_BUFFER BEGIN { \n", current->comm);
            binder_uintptr_t data_ptr;
            struct binder_buffer *buffer;

            if (get_user(data_ptr, (binder_uintptr_t __user *)ptr)) return -EFAULT;
            ptr += sizeof(binder_uintptr_t);
            printk(KERN_DEBUG "%s: BC_FREE_BUFFER data_ptr=%llx \n", current->comm, (u64)data_ptr);

            // 找到待释放的 binder_buffer
            buffer = binder_alloc_prepare_to_free(&proc->alloc, data_ptr);
            if(NULL == buffer) {
                pr_err("%s: binder_alloc_prepare_to_free cannot find binder_buffer with user_ptr=%llx \n",
                        current->comm, (u64)data_ptr);
                return -1;
            }
            printk(KERN_DEBUG "%s: got binder_buffer(@ %llx user_data=%llx free=%d) \n",
                    current->comm, (u64)buffer, (u64)buffer->user_data, buffer->free);

            // 释放 binder_buffer
            binder_alloc_free_buf(&proc->alloc, buffer);
            printk(KERN_DEBUG "%s: binder_alloc_free_buf() done! \n", current->comm);
            printk(KERN_DEBUG "%s: binder_thread_write cmd=BC_FREE_BUFFER   END } \n", current->comm);
            break;
        }
        case BC_TRANSACTION:
        case BC_REPLY: {
            char* cmd_str = cmd == BC_TRANSACTION ? "BC_TRANSACTION" : "BC_REPLY";
            printk(KERN_DEBUG "%s: binder_thread_write cmd=%s BEGIN { \n", current->comm, cmd_str);
            struct binder_transaction_data td;
            if (copy_from_user(&td, ptr, sizeof(td))) return -EFAULT;
            ptr += sizeof(td);
            binder_transaction(proc, thread, &td, cmd == BC_REPLY);
            printk(KERN_DEBUG "%s: binder_thread_write cmd=%s   END } \n", current->comm, cmd_str);
            break;
        }
        }
        *consumed = ptr - buffer;
    }
    return 0;
}


// 从list前端取出来一个元素，如果元素非空则将其从list删除掉；
static struct binder_work *binder_dequeue_work_head_ilocked(struct list_head *list) {
    struct binder_work *w;
    w = list_first_entry_or_null(list, struct binder_work, entry);
    if (w) list_del_init(&w->entry);
    return w;
}

static int binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
                binder_uintptr_t read_buffer, size_t size, binder_size_t *consumed, int non_block) {

    void __user *buffer = (void __user *)(uintptr_t)read_buffer;
    void __user *ptr = buffer + *consumed;

    uint32_t cmd;
    struct binder_transaction_data td;
    struct binder_work *w;
    struct binder_transaction *t = NULL;

    if(!list_empty(&proc->todo)) {
        // 获取binder_work结构体并，将list内该元素删除掉
        w = binder_dequeue_work_head_ilocked(&proc->todo);
        switch (w->type) {
        case BINDER_WORK_TRANSACTION: {
            printk(KERN_DEBUG "%s: binder_thread_read BINDER_WORK_TRANSACTION BEGIN { \n", current->comm);

            // container_of 是linux里面一个很巧妙的宏定义，这里不多展开了
            t = container_of(w, struct binder_transaction, work);
            printk(KERN_DEBUG "%s: binder_transaction(code=%d, data_size=%ld, offsets_size=%ld buffer->user_data=%llx) \n",
                    current->comm, t->code, t->buffer->data_size, t->buffer->offsets_size, (u64)t->buffer->user_data);

            // 如果是整个流程的前半程，则驱动将BR_TRANSACTION写给server端；如果是后半程，则驱动使用BR_REPLY将结果写给client端
            cmd = t->buffer->target_node ? BR_TRANSACTION : BR_REPLY;
            char* cmd_str = (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" : "BR_REPLY";

            // 根据 binder_buffer 中的 userdata 重新构造出一个 binder_transaction_data；
            // 计算 offsets 时计算ALIGN跟 binder_transaction() 函数里调用 binder_alloc_copy_user_to_buffer() 前计算ALIGN是对应的；
            // 需要特别说明的一点是：
            // 由于 t->buffer->user_data 本身就是userspace的地址，更准确地说，是 binder_thread_read 所在进程的vma范围内的userspace地址；
            // [原因见调用函数 binder_alloc_copy_user_to_buffer() 时的第一个参数，用的是target_proc的alloc，自然会映射到target_proc的vma范围内]
            // 所以，这里是可以直接赋值的，不需要做任何转换，后续userspace的程序拿到td.data.ptr.buffer和td.data.ptr.offsets也是可以直接读的；
            // 也就是说，binder_alloc_copy_user_to_buffer() 函数调用的 copy_from_user 看似是从userspace拷贝到kernel，
            // 而实际上实现的功能其实是 copy from source binder_proc userspace to target binder_proc userspace
            // binder 利用 “mmap映射vma到内核” + “映射存储待传输数据的物理页面到target_proc的vma” 这两项华丽操作，
            // 实现了 “一次IPC中数据只拷贝一次” 的终极目标；
            td.code = t->code;
            td.data_size = t->buffer->data_size;
            td.offsets_size = t->buffer->offsets_size;
            td.data.ptr.buffer  = (uintptr_t)t->buffer->user_data;
            td.data.ptr.offsets = (uintptr_t)t->buffer->user_data + ALIGN(t->buffer->data_size, sizeof(void *));

            // 将 binder_transaction_data 写到binder_thread_read的入参指定的地址里，用户进程在 ioctl 执行完毕后就能用了
            if (put_user(cmd, (uint32_t __user *)ptr)) return -EFAULT;
            ptr += sizeof(uint32_t);
            printk(KERN_DEBUG "%s: put_user: cmd=%s \n", current->comm, cmd_str);

            if (copy_to_user(ptr, &td, sizeof(td))) return -EFAULT;
            ptr += sizeof(td);
            printk(KERN_DEBUG "%s: copy_to_user: binder_transaction_data (code=%d data_size=%lld offsets_size=%lld data.ptr.buffer=%llx data.ptr.offsets=%llx) \n",
                current->comm, td.code, td.data_size, td.offsets_size, (u64)td.data.ptr.buffer, (u64)td.data.ptr.offsets);

            printk(KERN_DEBUG "%s: binder_thread_read BINDER_WORK_TRANSACTION   END } \n", current->comm);
            break;
        }
        case BINDER_WORK_TRANSACTION_COMPLETE: {
            printk(KERN_DEBUG "%s: binder_thread_read BINDER_WORK_TRANSACTION_COMPLETE BEGIN { \n", current->comm);
            cmd = BR_TRANSACTION_COMPLETE;
            kfree(w);
            if (put_user(cmd, (uint32_t __user *)ptr)) return -EFAULT;
            ptr += sizeof(uint32_t);
            printk(KERN_DEBUG "%s: binder_thread_read BINDER_WORK_TRANSACTION_COMPLETE   END } \n", current->comm);
            break;
        }
        }

    }
    return 0;
}


static int binder_ioctl_write_read(struct file *filp, unsigned int cmd,
                        unsigned long arg, struct binder_thread *thread) {
    int ret = 0;
    struct binder_proc *proc = filp->private_data;
    void __user *ubuf = (void __user *)arg;
    struct binder_write_read bwr;
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
        printk(KERN_DEBUG "%s: binder_ioctl_write_read copy_from_user ERROR \n", current->comm);
        ret = -EFAULT;
    }

    if (bwr.write_size > 0) {
        ret = binder_thread_write(proc, thread, bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
    }

    if (bwr.read_size > 0) {
        // 最后一个参数中 O_NONBLOCK 表示非阻塞的方式，即没有数据可读时，立即返回
        ret = binder_thread_read(proc, thread, bwr.read_buffer, bwr.read_size, &bwr.read_consumed,
                    filp->f_flags & O_NONBLOCK);
    }
    return ret;
}


static int binder_open(struct inode *nodp, struct file *filp) {
    printk(KERN_DEBUG "%s(%d|%d): binder_open \n", current->comm, current->tgid, current->pid);

    struct binder_proc *proc;
    proc = kzalloc(sizeof(*proc), GFP_KERNEL);
    if (proc == NULL) return -100;
    filp->private_data = proc;
    INIT_LIST_HEAD(&proc->todo);              // 初始化todo列表，后续的待处理的"work"都添加到这里
    proc->pid = current->group_leader->pid;
    proc->alloc.pid = current->group_leader->pid;
    INIT_LIST_HEAD(&proc->alloc.buffers);     // 本例子里用list来管理所有的 binder_buffer 对象，先初始化之

    // 这里直接记录一下两个proc信息，方便后续找到target_proc，亦即，让驱动本身起到了类似servicemanager的作用
    if( !strncmp(current->comm, CLIENT_PROC_NAME, strlen(CLIENT_PROC_NAME)) )
        proc_client = proc;
    if( !strncmp(current->comm, SERVER_PROC_NAME, strlen(SERVER_PROC_NAME)) )
        proc_server = proc;

    // 保存进程名，打印日志时使用，主要用于打印对端进程名字时
    memcpy(proc->name, current->comm, strlen(current->comm));
    proc->name[strlen(proc->name)] = '\0';

    return 0;
}


static void binder_vma_open(struct vm_area_struct *vma) {
    struct binder_proc *proc = vma->vm_private_data;
    printk(KERN_DEBUG
            "%d open vm area %lx-%lx (%ld K) vm_flags %lx pagep %lx \n",
            proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K,
            vma->vm_flags, (unsigned long)pgprot_val(vma->vm_page_prot));
}

static void binder_vma_close(struct vm_area_struct *vma) {
    struct binder_proc *proc = vma->vm_private_data;
    printk(KERN_DEBUG
            "%d close vm area %lx-%lx (%ld K) vm_flags %lx pagep %lx \n",
            proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K,
            vma->vm_flags, (unsigned long)pgprot_val(vma->vm_page_prot));
    binder_alloc_vma_close(&proc->alloc);
}

static vm_fault_t binder_vm_fault(struct vm_fault *vmf) {
    return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct binder_vm_ops = {
    .open = binder_vma_open,
    .close = binder_vma_close,
    .fault = binder_vm_fault,
};


static int binder_mmap(struct file *filp, struct vm_area_struct *vma) {
    printk(KERN_DEBUG "%s(%d|%d): binder_mmap PAGE_SIZE=%ld \n", current->comm, current->tgid, current->pid, PAGE_SIZE);
    int ret;
    struct binder_proc *proc = filp->private_data;
    const char *failure_string;

    printk(KERN_DEBUG "%s: %s: %d %lx-%lx (%ld K) vma=%llx \n",
            current->comm, __func__, proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K, (u64)vma);

    // binder要求userspace不能写mmap的存储空间，否则报错，
    // 也就意味着用户空间程序只能用 copy_from_user 和 copy_to_user 的方式与驱动进行数据传输
    if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
        ret = -EPERM;
        failure_string = "bad vm_flags";
        pr_err("%s: %d %lx-%lx %s failed %d \n", __func__, proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
        return ret;
    }

    // VM_DONTCOPY：表示在 fork() 时，该虚拟内存区域（VMA）不会被复制到子进程中
    // VM_MIXEDMAP：表示该虚拟内存区域是一个混合映射，可能包含多种类型的页面（如匿名页面和文件映射页面）
    vma->vm_flags |= VM_DONTCOPY | VM_MIXEDMAP;
    // 将 VM_MAYWRITE 标志从 vma->vm_flags 中清除，禁止该虚拟内存区域被动态修改为可写
    vma->vm_flags &= ~VM_MAYWRITE;

    vma->vm_ops = &binder_vm_ops;
    vma->vm_private_data = proc;

    // 初始化当前binder_proc的binder_alloc，此乃记录每个binder_proc的buffer分配的一个结构体
    return binder_alloc_mmap_handler(&proc->alloc, vma);
}

//由于binder_proc里简化为只存储了主线程，所以这个函数也被简化了
static struct binder_thread *binder_get_thread(struct binder_proc *proc) {
    if(proc->main_thread) {
        return proc->main_thread;
    }
    else {
        struct binder_thread *thread = kzalloc(sizeof(*thread), GFP_KERNEL);
        thread->proc = proc;
        proc->main_thread = thread;
        return thread;
    }
}

static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    struct binder_proc *proc = filp->private_data;
    struct binder_thread *thread = binder_get_thread(proc);
    if (thread == NULL) {
        return -100;
    }
    switch (cmd) {
    case BINDER_WRITE_READ:
        ret = binder_ioctl_write_read(filp, cmd, arg, thread);
        if (ret) {
            printk(KERN_DEBUG "%s: ERROR binder_ioctl_write_read ret=%d \n", current->comm, ret);
        }
        break;
    default:
        printk(KERN_DEBUG "%s: binder_ioctl: currently do not support cmd=%d \n", current->comm, cmd);
        ret = -EINVAL;
    }
    return ret;
}

static struct file_operations dev_fops = {
    .owner          = THIS_MODULE,
    .open           = binder_open,
    .mmap           = binder_mmap,
    .unlocked_ioctl = binder_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &dev_fops,
};

static int __init dev_init(void) {
    int ret;
    ret = misc_register(&misc);
    return ret;
}

static void __exit dev_exit(void) {
    misc_deregister(&misc);
}

module_init(dev_init);
module_exit(dev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("rightsubtree@hotmail.com");
