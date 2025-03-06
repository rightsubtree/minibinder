#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <unistd.h>

#include "binder.h"
#include "user_public.h"

extern void input(char* text, size_t max_len, char* prompt);
extern void replace(struct binder_state *bs);
extern int binder_parse(struct binder_state *bs, __u32 *ptr, int* stauts, char* result);


int main(int argc , char *argv[]) {
    struct binder_state *bs = binder_open(DRIVER, MMAP_LENGTH);

    print_maps();

    printf("Hello! This is a dummy binder toy with client, server, and driver \n");
    printf("Client can send 3 text to server, server will do replacement and reply result to client \n");

    while (1) {
        char select[MAX_INPUT];
        input(select, MAX_INPUT, "input 'r' to run, or 'q' to quit (both END with ENTER) \n");
        if (select[0] == 'r') {
            replace(bs);
        } else if (select[0] == 'q') {
            printf("bye ^_^ \n");
            break;
        } else {
            printf("invalid input, try again \n");
        }
    }
    return 0;
}


// 一个小函数，避免重复写类似的提示输入
void input(char* text, size_t max_len, char* prompt) {
    printf("%s \n", prompt);
    memset(text, 0, max_len);
    fgets(text, max_len, stdin);
    text[strlen(text) - 1] = '\0';  // 删除最后的换行
}


// 将采集到的输入打包到 binder_transaction_data 结构体内，发送给server端处理，并等待reply
void replace(struct binder_state *bs) {
    char* original = (char*) malloc(MAX_INPUT);
    char* oldsub   = (char*) malloc(MAX_INPUT);
    char* newsub   = (char*) malloc(MAX_INPUT);
    printf("\n");
    input(original, MAX_INPUT, "input the original text(<512), end with ENTER");
    input(oldsub,   MAX_INPUT, "input the oldsub to replace, end with ENTER");
    input(newsub,   MAX_INPUT, "input the newsub text, end with ENTER");

    // 传输时不携带字符串最后的'\0'，服务端获取后自己添加'\0'，打印debug信息时也自行添加
    binder_size_t data_size = strlen(original) + strlen(oldsub) + strlen(newsub);
    int obj_counts = 3;
    char* buffer = (char*) malloc(data_size);
    memset(buffer, 0, data_size);
    memcpy(buffer,                                     original, strlen(original));
    memcpy(buffer + strlen(original),                  oldsub,   strlen(oldsub)  );
    memcpy(buffer + strlen(original) + strlen(oldsub), newsub,   strlen(newsub)  );

    binder_size_t offsets[3];
    offsets[0] = 0;
    offsets[1] = strlen(original);
    offsets[2] = strlen(original) + strlen(oldsub);
    binder_size_t offsets_size = obj_counts * sizeof(binder_size_t);

    struct binder_transaction_data td;
    td.code = CODE_REPLACE_AND_REPLY;
    td.data_size = data_size;
    td.offsets_size = offsets_size;
    td.data.ptr.buffer = (binder_uintptr_t)buffer;
    td.data.ptr.offsets = (binder_uintptr_t)offsets;

    // 这里的out相当于标准binder里面 IPCThreadState 类里面的域 `Parcel mOut` ;
    // 第一个数据是 BC_TRANSACTION，类型是 __32，其后是一个 binder_transaction_data 结构体
    binder_size_t write_size = sizeof(__u32) + sizeof(struct binder_transaction_data);
    __u32* write_buffer = (__u32 *)malloc(write_size);
    *write_buffer = BC_TRANSACTION;
    memcpy(write_buffer + 1, &td, sizeof(struct binder_transaction_data));

    // 先打印一下看看
    print_binder_transaction_data((struct binder_transaction_data *)(write_buffer + 1));

    // write_buffer已经是地址了，所以前面不能添加&符了，
    // 否则运行时很可能不会报错，但binder_write_read.write_buffer指向的是“这个地址的地址”后面的内存，
    // 里面的数据毫无意义，所以server端极大概率不会有响应；
    // 哎，曾经在这里困扰了一个多小时……
    binder_write(bs, write_buffer, write_size);

    binder_size_t read_size = sizeof(__u32) + sizeof(struct binder_transaction_data);
    __u32* read_buffer = (__u32 *)malloc(read_size);

    char result[MAX_INPUT *2 + 1];
    memset(result, 0, MAX_INPUT *2 + 1);

    // 循环等待，直到等到最后结果
    while(1) {
        // 休息200ms，否则可能导致进程长期占用CPU，作为一个演示程序，我们不关心进程的休眠唤醒等细节
        usleep(200);
        // 先读一下看有没有驱动传递来的命令/回复
        binder_read(bs, read_buffer, read_size); // binder_read内部每次都会先将read_buffer置空
        // 解析
        int status = 0xFF;
        binder_parse(bs, read_buffer, &status, result);
        // 解析成功
        if(status == 0) {
            printf("success! result = %s \n \n", result);
            // 退出循环等待，重新回到用户选择功能
            break;
        }
    }

    // 走到这里，说明解析成功退出while循环了，把该释放的内存释放掉
    free(original);
    free(oldsub);
    free(newsub);
    free(buffer);
    free(write_buffer);
    free(read_buffer);
}


// 解析指针ptr携带的用ioctl从驱动读取到的值，
// 如果获得了reply，则将结果保存到result所知内存区域，并将stauts设置为0
int binder_parse(struct binder_state *bs, __u32 *ptr, int* stauts, char* result) {
    struct binder_transaction_data td;
    __u32 cmd = *ptr;

    // client端仅仅需要处理 BR_TRANSACTION_COMPLETE 和 BR_REPLY
    switch (cmd) {
    case BR_TRANSACTION_COMPLETE: {
        printf("BR_TRANSACTION_COMPLETE \n");  // 作为测试程序，这里啥也不需要干
        break;
    }
    case BR_REPLY: {
        printf("BR_REPLY \n");
        memcpy(&td, ++ptr, sizeof(struct binder_transaction_data));
        print_binder_transaction_data(&td);    // 先打印一下看看

        if(BR_REPLY == cmd) {
            if(CODE_REPLACE_AND_REPLY == td.code) {
                if(td.offsets_size / sizeof(binder_size_t) != 1) {
                    printf("ERROR: wrong obj counts \n");
                    return -1;
                }
                memcpy(result, (char*)td.data.ptr.buffer, td.data_size); // 只有一个obj时，计算就很简单了
                *stauts = 0;                                             // 记录解析状态

                // 最后一步，让驱动释放 BR_REPLY 时使用的 binder_buffer
                struct {
                    uint32_t cmd_free;
                    binder_uintptr_t buffer;
                } __attribute__((packed)) data;

                data.cmd_free = BC_FREE_BUFFER;
                data.buffer = td.data.ptr.buffer;
                binder_write(bs, &data, sizeof(data));

                printf("write BC_FREE_BUFFER buffer=%llx \n", data.buffer);
            }
        }
        break;
    }
    }
    return 0;
}
