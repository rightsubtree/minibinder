#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <time.h>
#include <stdint.h>

#include "binder.h"
#include "user_public.h"

extern int binder_parse(struct binder_state *bs, __u32 *ptr);
extern int replace_and_reply(struct binder_state *bs, struct binder_transaction_data *td);
extern void replace(const char *str, const char *old, const char *new, char *result);
extern int binder_parse(struct binder_state *bs, __u32 *ptr);


int main(int argc , char *argv[]) {
    struct binder_state *bs = binder_open(DRIVER, MMAP_LENGTH);

    print_maps();

    binder_size_t read_size = sizeof(__u32) + sizeof(struct binder_transaction_data);
    __u32* read_buffer = (__u32 *)malloc(read_size);

    // 循环等待
    while(1) {
        // 休息200ms，否则可能导致进程长期占用CPU，作为一个演示程序，我们不关心进程的休眠唤醒等细节
        usleep(200);
        // 先读一下看有没有驱动传递来的命令
        binder_read(bs, read_buffer, read_size); // binder_read内部每次都会先将read_buffer置空
        // 然后解析，没有读到也无所谓，对于空数据，binder_parse内部会啥也不干直接退出
        binder_parse(bs, read_buffer);
    }
    return 0;
}


int binder_parse(struct binder_state *bs, __u32 *ptr) {
    struct binder_transaction_data td;
    __u32 cmd = *ptr;

    // server端仅仅需要处理 BR_TRANSACTION 和 BR_TRANSACTION_COMPLETE
    switch (cmd) {
    case BR_TRANSACTION: {
        printf("BR_TRANSACTION \n");
        memcpy(&td, ++ptr, sizeof(struct binder_transaction_data));
        print_binder_transaction_data(&td);    // 先打印一下看看

        // 根据code决定服务端执行哪些功能
        if(CODE_REPLACE_AND_REPLY == td.code) {
            replace_and_reply(bs, &td);
        }
        break;
    }
    case BR_TRANSACTION_COMPLETE: {
        printf("BR_TRANSACTION_COMPLETE \n");  // 作为测试程序，这里啥也不需要做
        break;
    }
    }

    return 0;
}


int replace_and_reply(struct binder_state *bs, struct binder_transaction_data *td) {
    int obj_count = td->offsets_size / sizeof(binder_size_t);
    if(obj_count != 3) {
        printf("ERROR! should have 3 data objs \n");
        return -1;
    }
    // 取得3个字符串
    char* objs[3];
    for(int i = 0; i < 3; i++) {
        int offset_current = *((__u64*)td->data.ptr.offsets + i);
        int offset_next = (i < obj_count-1) ? *( (__u64*)td->data.ptr.offsets + (i + 1)) : td->data_size;
        int obj_length = offset_next - offset_current;
        char* p_begin = (char*)td->data.ptr.buffer + offset_current;
        objs[i] = (char*) malloc(MAX_INPUT + 1);
        memset(objs[i], 0, obj_length + 1);
        memcpy(objs[i], p_begin, obj_length);
        printf("get obj: %s \n", objs[i]);
    }

    char* result = (char*) malloc(MAX_INPUT * 2 + 1);
    replace(objs[0], objs[1], objs[2], result);
    printf("replace result: %s \n", result);
    binder_size_t offsets[1] = {0};

    for(int i = 0; i < 3; i++) {
        free(objs[i]);
    }

    // 一个data携带两个cmd
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
        uint32_t cmd_reply;
        struct binder_transaction_data td;
    } __attribute__((packed)) data;

    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = td->data.ptr.buffer;
    data.cmd_reply = BC_REPLY;
    data.td.target.ptr = 0;
    data.td.cookie = 0;
    data.td.code = CODE_REPLACE_AND_REPLY;
    data.td.flags = 0;
    data.td.data_size = strlen(result);
    data.td.offsets_size = sizeof(binder_size_t) * 1;
    data.td.data.ptr.buffer = (binder_uintptr_t)result;
    data.td.data.ptr.offsets = (binder_uintptr_t)offsets;

    int ret = binder_write(bs, &data, sizeof(data));

    printf("write BC_FREE_BUFFER buffer=%llx \n", data.buffer);
    printf("write BC_REPLY data_size=%d offsets_size=%d data.ptr.buffer=%llx data.ptr.offsets=%llx \n",
            data.td.data_size, data.td.offsets_size, data.td.data.ptr.buffer, data.td.data.ptr.offsets);

    free(result);
    return ret;
}


// 好吧，这是我们的服务端干活的“业务代码” ^_^
// 将str里第一次出现old_substr的地方替换成new_substr，并保存到新的字符串result里面
// 如果str里面不存在待替换的子串old_substr，则直接拷贝一份原始字符串到result里
void replace(const char *str, const char *old, const char *new, char *result) {
    char *pos = strstr(str, old);
    if (pos != NULL) {
        strncpy(result, str, pos - str);
        result[pos - str] = '\0';
        strcat(result, new);
        strcat(result, pos + strlen(old));
    }
    else {
        strcpy(result, str);
    }
}
