obj-m := minibinder.o
minibinder-objs := binder.o binder_alloc.o
CURRENT_PATH := $(shell pwd)
LINUX_KERNEL := $(shell uname -r)
LINUX_KERNEL_PATH := /usr/src/linux-headers-$(LINUX_KERNEL)

all: minibinder client server

minibinder:
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

client: client.o user_public.o
	gcc -o client client.o user_public.o

client.o: client.c
	gcc -c client.c -o client.o

server: server.o user_public.o
	gcc -o server server.o user_public.o

server.o: server.c
	gcc -c server.c -o server.o

user_public.o: user_public.c
	gcc -c user_public.c -o user_public.o

clean:
	rm -f *.o *.ko *.mod *.mod.c modules.order Module.symvers .*.cmd
	rm -f client
	rm -f server
