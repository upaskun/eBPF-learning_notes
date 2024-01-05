#!/usr/bin/python3
from bcc import BPF
from time import sleep
program = r"""
BPF_HASH(counter_table);
int execve_hello(void *ctx){
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
int openat_hello(void *ctx){
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
execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve, fn_name="execve_hello")
openat = b.get_syscall_fnname("openat")
b.attach_kprobe(event=openat,fn_name="openat_hello")
while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
