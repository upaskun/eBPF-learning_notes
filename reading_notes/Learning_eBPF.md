# Learning eBPF阅读笔记

## eBPF的基本使用

### 基础概念

#### _kprobes_

能够为**几乎**任何内核代码设置trap

kprobes文档，下次一定(收藏夹吃灰去吧)
- [ ] https://docs.kernel.org/trace/kprobes.html

#### 基础数据结构
eBPF _maps_ : 用于用户态程序和eBPF程序的数据交换

