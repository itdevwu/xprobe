#define SEC(name) __attribute__((section(name), used))

SEC("uprobe")
int xprobe_uprobe(void *context)
{
    (void)context;
    return 0;
}

char _license[] SEC("license") = "GPL";
