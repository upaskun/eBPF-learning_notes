from bcc import BPF

program = """
BPF_PERF_OUTPUT(output);

struct data_t {
    int pid;
    char command[16];
    char message[20];
};

int hello(void *ctx){
    int i = 0;
    struct data_t data = {};
    char message_odd[] = "the pid is odd!";
    char message_even[] = "the pid is even!";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    int n = data.pid%2;
    if (n==0){
        bpf_probe_read_kernel(&data.message, sizeof(data.message), message_even);
    }else{
        bpf_probe_read_kernel(&data.message, sizeof(data.message), message_odd);
    }
    bpf_get_current_comm(&data.command, sizeof(data.command));
    
    output.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve");
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.command.decode()} " + \
            f"{data.message.decode()}")

b["output"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
