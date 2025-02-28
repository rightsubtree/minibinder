#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include "binder.h"
#include "user_public.h"


// 打开驱动设备节点，并完成mmap
struct binder_state *binder_open(const char* driver, size_t mapsize) {
    struct binder_state *bs;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) {
        fprintf(stderr, "binder: cannot open %s (%s)\n", driver, strerror(errno));
        goto fail_open;
    }

    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n", strerror(errno));
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}


// 通过ioctl从binder驱动读取长度len的数据，将读取到的内容写入data内
int binder_read(struct binder_state *bs, void *data, size_t len) {
    memset(data, 0, len);   // data将来要存储新的数据，所以先清空一下，好习惯
    struct binder_write_read bwr;
    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;
    bwr.read_size = len;
    bwr.read_consumed = 0;
    bwr.read_buffer = (uintptr_t)data;
    int res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_read: ioctl failed (%s)\n", strerror(errno));
    }
    return res;
}


// 通过ioctl将data指向的长度为len的内容写入binder驱动
int binder_write(struct binder_state *bs, void *data, size_t len) {
    struct binder_write_read bwr;
    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t)data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    int res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n", strerror(errno));
    }
    return res;
}


// 打印一个binder_transaction_data结构体的内容到屏幕上，仅用于debug
void print_binder_transaction_data(struct binder_transaction_data *td) {
    printf("\n");
    printf("binder_transaction_data: \n");
    printf("code=%d \n", td->code);
    printf("data_size=%d \n", td->data_size);
    printf("offsets_size=%d \n", td->offsets_size);
    int obj_count = td->offsets_size / sizeof(binder_size_t);
    for(int i = 0; i < obj_count; i++) {
        // data.ptr.offsets 里面保存了每个obj起始位置的偏移量，
        // 下一个obj的offset，同时也是当前obj的终止位置，所以下一个obj的偏移量减去当前obj的偏移量，得到的是当前obj的大小
        // 但如果到了最后一个obj，则指针btd->data.ptr.offsets+(i+1) 会直接指向到offsets范围的外下一个字节，
        // 亦即没有办法获得最后一个obj的终止位置，幸好data_size其实就是最后一个obj的终止位置
        int offset_current = *((__u64*)td->data.ptr.offsets + i);
        int offset_next = (i < obj_count-1) ? *( (__u64*)td->data.ptr.offsets + (i + 1)) : td->data_size;
        int obj_length = offset_next - offset_current;
        char* p_begin = (char*)td->data.ptr.buffer + offset_current;  // 每个obj在data的buffer中的开头位置
        char* temp = (char *)malloc(obj_length + 1);                  // +1 是为了最后能留一个'\0'
        memset(temp, 0, obj_length + 1);
        memcpy(temp, p_begin, obj_length);
        printf("obj-%d: offset=%02d data=%s \n", i, offset_current, temp);
        free(temp);
    }
    printf("\n");
}

// 打印一下用户空间程序的 /proc/self/maps 内容，便于查看堆区、栈区、内存映射区等的范围
void print_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return;
    }
    printf("/proc/self/maps: \n\n");
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }
    printf("\n");
    fclose(fp);
}
