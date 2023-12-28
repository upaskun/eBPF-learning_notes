# Learning eBPF阅读笔记

## eBPF的基本使用

### 基础概念

#### _kprobes_

能够为**几乎**任何内核代码设置trap

kprobes文档，下次一定(收藏夹吃灰去吧)
- [ ] https://docs.kernel.org/trace/kprobes.html

第一个程序 

```python
#!/bin/python

from bcc import BPF

program = r"""
int hello(void *ctx){
  bpf_trace_printk("Hello, World!");
  return 0;
}
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print() 
```


#### 基础数据结构

eBPF _maps_ : 用于用户态程序和eBPF程序的数据交换


####  userspace&kernel传递数据的N种方式

##### 1. Hash Table Map

bcc 中可以通过定义BPF_HASH来定义map，这个map是用户和内核都可读的

```python
#!/usr/bin/python3
from bcc import BPF
from time import sleep
program = r"""
BPF_HASH(counter_table);
int hello(void *ctx){
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p != 0){
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);
    return 0;
}
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
```

##### 2. perf & ring buffer map

perf是一个linux内核中的性能分析框架，可以收集分析来自内核态和用户态程序的性能。

perf subsystem 可以向用户态传递一些内核的信息。

eBPF中可以使用perf buffer来存储kernel信息，在更高版本中还支持使用BPF ring buffer来收集kernel的数据。

使用perf buffer是一种更为灵活的做法，因为可以支持用户自定义的结构体，不过写法上比hash map的稍微复杂一些，下面写个模板

```python
program = r"""
BPF_PERF_OUTPUT(output); //定义用户和内核之间传递数据的变量名
struct user_struct {
  // 按需定义结构体
};
int specfic_func(void *ctx){
  struct user_struct data = {};
  //...
  output.perf_submit(ctx,&data, sizeof(data); // 将要传递的信息放入perf buffer
  return 0;
}
“”“
b = BPF(text=program)
//...

def print_event(cpu,data, size):
  data = b["output"].event(data); // 读取内核传来的数据
  //...

b["output"].open_perf_buffer(print_event) //将要操作的函数传给perf buffer
while True:
  b.perf_buffer_poll()
```

#### 函数调用

在从Linux内核4.16及LLVM 6.0之前，eBPF只支持内联函数。 如果使用 bcc那就是--高版本也不行🤷
但是！ bcc作为非常火热的eBPF程序，必须得支持一些复杂的功能昂，解决之道就在 **tail calls** 

##### tail calls

tail calls 中文称为尾部调用，在eBPF中它的功能是执行别的eBPF程序然后取代执行的上下文。 

chatGPT的解释是
> 尾部调用是指函数的最后一个动作是调用另一个函数。具体来说，被调用的函数是当前函数的返回值。在尾部调用中，没有其他的操作需要执行，因此可以立即释放当前函数的栈帧，这样能够减少递归调用或者连续调用函数时所使用的内存空间。
> 尾部调用的主要优点是减少内存使用，尤其对于递归算法来说，可以避免栈溢出。
> 例如，在下面的代码中，函数 functionA 中的最后一个操作是调用函数 functionB，这就是尾部调用：

```c

def functionA(n):
    if n == 0:
        return 1
    else:
        return functionB(n-1)

def functionB(n):
    return n * functionA(n-1)
```
