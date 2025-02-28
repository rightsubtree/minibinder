#ifndef _LINUX_USER_PUBLIC_H
#define _LINUX_USER_PUBLIC_H

#define DRIVER                    "/dev/minibinder"
#define MMAP_LENGTH               (4096 * 10)
#define MAX_INPUT                 512
#define CODE_REPLACE_AND_REPLY    1

struct binder_state {
    int fd;
    void *mapped;
    size_t mapsize;
};

extern struct binder_state *binder_open(const char* driver, size_t mapsize);
extern int binder_read(struct binder_state *bs, void *data, size_t len);
extern int binder_write(struct binder_state *bs, void *data, size_t len);
extern void print_binder_transaction_data(struct binder_transaction_data *td);
extern void print_maps();


#endif  /*_LINUX_USER_PUBLIC_H*/