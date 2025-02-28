# minibinder 一个可以在PC上运行的极简binder



## 关于

这是一个基于android 的 kernel v4.19 （大约对应于Android 9~10前后）改出来的极简的binder，用于演示binder数据传输的主要逻辑，可以在Linux amd64 环境编译和运行；

为了简化逻辑，对binder原生代码做了非常多的裁剪，仅仅留下了最核心的流程；

驱动侧代码约800多行，server端和client端代码总计约400多行，总计1200行左右；



## 使用方法

### 1、编译

清空：       `make clean`

编译全部：`make all`

也可以选择单独编译：

仅编译内核模块：`make minibinder`

仅编译客户端：    `make client`

仅编译服务端：    `make server`

### 2、添加和删除内核模块

添加并允许应用读写：
`sudo insmod minibinder.ko && sudo chmod 777 /dev/minibinder`

删除模块：
`sudo rmmod minibinder`

查看模块：
`sudo lsmod | grep minibinder`

更新ko相关的代码后，需要重新rmmod和insmod方可生效；
删除模块时，如果提示ERROR: Module minibinder is in use，则需要关闭所有client和server进程后，再次执行一遍删除模块命令；

### 3、运行：

在两个终端tab里分别执行 `./server` 和 `./client`

按照client的提示，选择和输入，查看运行结果；

### 4、日志：

client 和 server的日志直接打在屏幕上；

内核日志请使用命令 dmesg 命令查看（建议开始测试前，用 sudo dmesg -c 命令先清空历史记录）



## 详细讲解

稍后提供