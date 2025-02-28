#include <linux/highmem.h>

#include "binder_alloc.h"
#include "binder.h"

static DEFINE_MUTEX(binder_alloc_mmap_lock);

static inline void binder_alloc_set_vma(struct binder_alloc *alloc, struct vm_area_struct *vma) {
    if (vma) alloc->vma_vm_mm = vma->vm_mm;
    smp_wmb();
    alloc->vma = vma;
}

void binder_alloc_vma_close(struct binder_alloc *alloc) {
    binder_alloc_set_vma(alloc, NULL);
}


// mmap后，初始化当前 binder_proc 的 binder_alloc信息
int binder_alloc_mmap_handler(struct binder_alloc *alloc, struct vm_area_struct *vma) {
    int ret;
    const char *failure_string;
    int page_count = (vma->vm_end - vma->vm_start) / PAGE_SIZE;   // 用户空间的虚拟内存对应多少个内核页面空间

    mutex_lock(&binder_alloc_mmap_lock);
    if (alloc->buffer) {
        ret = -EBUSY;
        failure_string = "already mapped";
        goto err_already_mapped;
    }
    // 永远指向mmap时vma的start位置，一旦mmap后就不变化了，后续会用alloc->buffer来计算相对页序号、页内偏移值等
    alloc->buffer = (void __user *)vma->vm_start;
    mutex_unlock(&binder_alloc_mmap_lock);

    // binder_alloc的buffer_size表示当前binder_proc能使用的最大缓冲区空间，也是mmap后就固定了，等于mmap时指定的参数大小
    alloc->buffer_size = vma->vm_end - vma->vm_start;

    // 本例中没有用binder_lru_page结构体，pages是二级指针（相当于指针的数组的起始地址），其每个元素都是一个指向内核page的指针
    alloc->pages = kzalloc(page_count * sizeof(alloc->pages[0]), GFP_KERNEL);
    if (alloc->pages == NULL) {
        ret = -ENOMEM;
        failure_string = "alloc page array";
        goto err_alloc_pages_failed;
    }

    // 为vma虚拟内存创建对应的 binder_buffer ，需要注意的是，此时并没有给binder_buffer分配内核内存页面
    // 为了简化，我们让每个binder_buffer的大小都正好是一个page，后续分配和释放，都以整个page为单位
    // 所以 binder_alloc的域buffers这个列表也有 page_count 个元素，即 alloc->pages 和 alloc->buffers 的元素一一对应
    for(int i = 0; i < page_count; i++) {
        struct binder_buffer *buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
        if (!buffer) {
            ret = -ENOMEM;
            failure_string = "alloc buffer struct";
            goto err_alloc_buf_struct_failed;
        }
        buffer->user_data = alloc->buffer + PAGE_SIZE * i;
        // 原生binder里面binder_alloc用红黑树管理buffers，这里简化为list
        list_add_tail(&buffer->entry, &alloc->buffers);
        buffer->free = 1;
    }

    // 打印一下看看，后面日志里可以跟这里的地址对照
    // 包括 binder_buffer 本身地址，后面寻找空闲buffer时可对照，TNND，为了让大家搞明白，我真是操碎了心啊
    struct binder_buffer *bb;
    int index = 0;
    list_for_each_entry(bb, &alloc->buffers, entry) {
        printk(KERN_DEBUG "%s: alloc->buffers <%d> binder_buffer(@ %llx user_data=%llx free=%d) \n",
                current->comm, index++, (u64)bb, (u64)bb->user_data, bb->free);
    }

    // 保存一个名字，主要是为了方便日志更易读
    memcpy(alloc->name, current->comm, strlen(current->comm));
    alloc->name[strlen(alloc->name)] = '\0';

    binder_alloc_set_vma(alloc, vma);
    alloc->vma_vm_mm = vma->vm_mm;
    mmgrab(alloc->vma_vm_mm);

    return 0;

err_alloc_buf_struct_failed:
    kfree(alloc->pages);
    alloc->pages = NULL;
err_alloc_pages_failed:
    mutex_lock(&binder_alloc_mmap_lock);
    alloc->buffer = NULL;
err_already_mapped:
    mutex_unlock(&binder_alloc_mmap_lock);
    printk(KERN_DEBUG "%s: %d %lx-%lx %s failed %d \n",
            __func__, alloc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
    return ret;
}


// 原生binder的这个函数逻辑比较复杂，原因是要处理各种情况，包括但不限于：
// binder_buffer跨内存页、binder_buffer大小小于内存页、binder_buffer起始地址与内存页不对齐、
// 分配/释放 binder_buffer 时是否需要分配/释放内存页 等等；
// 本例子里简化为仅仅分配或者释放一页内存（亦即参数end实际没有使用），所以要求参数start是一个pagesize的起点
static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
                                void __user *start, void __user *end) {
    printk(KERN_DEBUG "%s: binder_update_page_range: allocate=%d start=%llx end=%llx \n",
            current->comm, allocate, (u64)start, (u64)end);
    void __user *page_addr = start;
    struct vm_area_struct *vma = alloc->vma;
    size_t index = (page_addr - alloc->buffer) / PAGE_SIZE;

    if (end <= start) {
        printk(KERN_DEBUG "%s: binder_update_page_range ERROR: end <= start \n", current->comm);
        return 0;
    }
    printk(KERN_DEBUG "%s: %s(%d) %s pages for userspace %llx--%llx \n",
            current->comm, alloc->name, alloc->pid, allocate ? "allocate" : "free", (u64)start, (u64)end);

    // 分配一页
    if (allocate == 1) {
        // 获得一个page
        // 注意，这里 alloc_page 函数返回的是一个物理页面的地址，并不是虚拟地址，不能直接执行读写操作；
        // 执行读写前，需要用 kmap 做映射，参考本文件内的函数 binder_alloc_copy_user_to_buffer 的做法；
        struct page* page_ptr = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
        if (!page_ptr) {
            pr_err("%d: binder_update_page_range failed alloc_page at %pK\n", alloc->pid, page_addr);
            return 0;
        }
        alloc->pages[index] = page_ptr; // 记录到alloc的列表内，便于后续释放内存时检索
        printk(KERN_DEBUG "%s: allocate: alloc->pages[%ld] <--> kernel page_ptr=%llx <--> userspace page_addr=%llx \n",
                current->comm, index, (u64)page_ptr, (u64)page_addr);

        // 将page_ptr指向的一页内核内存空间和用户空间的 page_addr 关联起来，
        // 此后，用户空间就可以从 page_addr 读取到 page_ptr 所在页内存的数据
        if (vm_insert_page(vma, (unsigned long)page_addr, page_ptr)) {
            pr_err("%d: binder_update_page_range failed to map page at %llx in userspace\n", alloc->pid, (u64)page_addr);
            __free_page(page_ptr); // 避免内核page泄露
            return 0;
        }
        printk(KERN_DEBUG "%s: vm_insert_page(%llx, %llx, %llx) \n", current->comm, (u64)vma, (u64)page_addr, (u64)page_ptr);
        return 0;
    }
    // 释放一页
    else {
        // 本例是每次分配和释放整个page，所以此时需要将整页从vma移除，否则下次使用相同的page_addr调用vm_insert_page时必现错误
        zap_page_range(vma, (unsigned long)page_addr, PAGE_SIZE);    // vm_insert_page 的逆操作
        // 释放整个page，并更新alloc->pages 列表对应的指针值为NULL
        struct page* page_ptr = alloc->pages[index];
        __free_page(page_ptr);                        // alloc_page 的逆操作
        alloc->pages[index] = NULL;

        printk(KERN_DEBUG "%s: free: alloc->pages[%ld] <--> kernel page_ptr %llx <--> userspace page_addr %llx \n",
                current->comm, index, (u64)page_ptr, (u64)page_addr);
        return 0;
    }
}


// 遍历alloc->buffers列表，找到 user_ptr 指针所对应的那个待释放的 binder_buffer
struct binder_buffer *binder_alloc_prepare_to_free(struct binder_alloc *alloc, uintptr_t user_ptr) {
    struct binder_buffer *buffer;
    void __user *uptr = (void __user *)user_ptr;
    list_for_each_entry(buffer, &alloc->buffers, entry) {
        printk(KERN_DEBUG "%s: binder_alloc_prepare_to_free list_for_each_entry binder_buffer(@ %llx user_data=%llx free=%d) \n",
            current->comm, (u64)buffer, (u64)buffer->user_data, buffer->free);
        if(uptr == buffer->user_data) {
            printk(KERN_DEBUG "%s: binder_alloc_prepare_to_free: Find the buffer to free \n", current->comm);
            return buffer;
        }
    }
    // 走完了list_for_each_entry，说明没有找到合适的，返回NULL
    return NULL;
}


// 释放指定参数所对应的 binder_buffer
// 原生binder的逻辑相对复杂，包含合并连续空闲空间、整个物理page都释放后才能释放物理页面等逻辑；
// 这里的做法非常简单，释放 binder_buffer 的同时也会释放其对应的物理页面；
void binder_alloc_free_buf(struct binder_alloc *alloc, struct binder_buffer *buffer) {

    printk(KERN_DEBUG "%s: %s(%d) binder_alloc_free_buf binder_buffer(@ %llx user_data=%llx free=%d) \n",
            current->comm, alloc->name, alloc->pid, (u64)buffer, (u64)buffer->user_data, buffer->free);

    binder_update_page_range(alloc, 0,
            (void __user *)PAGE_ALIGN((uintptr_t) buffer->user_data),
            (void __user *)PAGE_ALIGN((uintptr_t) buffer->user_data + PAGE_SIZE));

    buffer->data_size = 0;
    buffer->offsets_size = 0;
    buffer->pid = 0;
    buffer->free = 1;
}


// 从alloc->buffers列表中，找到一个空闲buffer，并将这个buffer与一页物理内存以及用户空间虚拟地址关联起来
struct binder_buffer *binder_alloc_new_buf(struct binder_alloc *alloc, size_t data_size, size_t offsets_size, int pid) {
    struct binder_buffer *buffer;

    // 从alloc的buffers列表中找一个空闲的出来使用，单线程环境下，找到的buffer应该是vma的start，
    // 然后调用binder_update_page_range时，相当于让vma->start关联到内核分配出的新的一个page的内存
    list_for_each_entry(buffer, &alloc->buffers, entry) {
        printk(KERN_DEBUG "%s: binder_alloc_new_buf list_for_each_entry binder_buffer(@ %llx user_data=%llx free=%d) \n",
                current->comm, (u64)buffer, (u64)buffer->user_data, buffer->free);
        if(buffer->free) {
            printk(KERN_DEBUG "%s: binder_alloc_new_buf: GOT free buffer \n", current->comm);

            binder_update_page_range(alloc, 1,
                (void __user *)PAGE_ALIGN((uintptr_t) buffer->user_data),
                (void __user *)PAGE_ALIGN((uintptr_t) buffer->user_data + PAGE_SIZE));

            buffer->data_size = data_size;
            buffer->offsets_size = offsets_size;
            buffer->pid = pid;  // 标记已经被某个进程占用
            buffer->free = 0;   // 标记一下已经占用

            return buffer;
        }
    }
    // 走完了list_for_each_entry，说明没有找到合适的
    return NULL;
}


// 查询指定的 binder_buffer地址 + buffer_offset 偏移后（注意，二者相加后可能大于PAGE_SIZE）， 对应的内核page物理地址，
// 物理地址数据来自当前进程的 binder_alloc 的 pages 的某个下标里，
// 这个 binder_alloc->pages[index] 是在 binder_alloc_free_buf --> binder_update_page_range 过程中设置的；
static struct page *binder_alloc_get_page(struct binder_alloc *alloc, struct binder_buffer *buffer,
            binder_size_t buffer_offset, pgoff_t *pgoffp) {
    printk(KERN_DEBUG "%s: binder_alloc_get_page: alloc->buffer=%llx binder_buffer(@ %llx user_data=%llx free=%d) buffer_offset=%llx \n",
            current->comm, (u64)alloc->buffer, (u64)buffer, (u64)buffer->user_data, buffer->free, (u64)buffer_offset);

    // alloc->buffer永远等于虚拟内存的vma->vm_start，而 buffer->user_data 是某个已经分配空间的 binder_buffer 的起始地址，
    // (buffer->user_data - alloc->buffer) 就是某个 binder_buffer 相对vma_start的偏移，
    // 再加上buffer_offset（即buffer内的offset），就是某个地址相对vma_start的偏移；
    // 另外，这些参与计算的地址都是用户空间的虚拟地址
    binder_size_t buffer_space_offset = buffer_offset + (buffer->user_data - alloc->buffer);

    // 求buffer_space_offset相对自己所在页的页首的偏移
    pgoff_t pgoff = buffer_space_offset & ~PAGE_MASK;

    // PAGE_SIZE=4k时，PAGE_SHIFT=12，所以 >> PAGE_SHIFT 相当于除以PAGE_SIZE，结果是获取相对页序号（编号从0开始）
    size_t index = buffer_space_offset >> PAGE_SHIFT;  // 获取相对于vma->vm_start的页序号
    printk(KERN_DEBUG "%s: binder_alloc_get_page: index=%ld pgoff=%llx page=%llx \n",
            current->comm, index, (u64)pgoff, (u64)alloc->pages[index]);

    *pgoffp = pgoff;
    return alloc->pages[index];
}


// 从参数 from 所指向的用户空间，拷贝 bytes 个字节内容，
// 到指定的 buffer + buffer_offset 的位置（这两个地址相加后，可能跨越了PAGE_SIZE）；
unsigned long binder_alloc_copy_user_to_buffer(struct binder_alloc *alloc, struct binder_buffer *buffer,
                                binder_size_t buffer_offset, const void __user *from, size_t bytes) {
    while (bytes) {
        unsigned long size;
        unsigned long ret;
        struct page *page;
        pgoff_t pgoff;
        void *kptr;
        void* kptr_page;

        // 获得页面物理地址
        page = binder_alloc_get_page(alloc, buffer, buffer_offset, &pgoff);

        // min_t(type, x, y) 用于从type类型的两个数x和y中找到一个较小的
        // 这个比较的意思是，如果需要copy的字节数bytes未达到本page的最后（即不跨页）则直接写bytes个；
        // 如果跨页了，则先copy本页内剩余部分，后面的部分留到while循环的下一轮copy；
        // 原生binder这样做，是为了能充分利用每一个字节的空间，做得还是很细致的，不服不行！
        // 当然，本例子里肯定不存在跨页的情况；
        size = min_t(size_t, bytes, PAGE_SIZE - pgoff);

        // kmap函数将物理页面映射到内核的虚拟地址空间中，返回一个虚拟地址，通过这个虚拟地址，内核可以访问物理内存；
        // kmap()是与 kunmap()配对使用的；kmap()映射内存，kunmap()释放映射；
        // kptr = kmap(page) + pgoff;  // 本例子把原生的这行拆成下面两行，目标是为了打印出来kmap(page)的结果
        kptr_page = kmap(page);
        kptr = kptr_page + pgoff;
        printk(KERN_DEBUG "%s: binder_alloc_copy_user_to_buffer: kmap(%llx) got kernel virtual addr %llx \n",
                current->comm, (u64)page, (u64)kptr_page);

        // 忙活了半天，终于可以做正儿八经的copy了
        ret = copy_from_user(kptr, from, size);

        printk(KERN_DEBUG "%s: binder_alloc_copy_user_to_buffer: copy_from_user(%llx, %llx, %ld) \n",
                current->comm, (u64)kptr, (u64)from, size);

        // 释放本页映射
        kunmap(page);

        // copy_from_user 的返回值是“未能成功复制的字节数”，
        // 所以这里return的值含义是整体上剩余未copy的字节数；当然，一般走不到这里；
        if (ret) return bytes - size + ret;

        bytes -= size;
        from += size;
        buffer_offset += size;
    }
    return 0;
}
