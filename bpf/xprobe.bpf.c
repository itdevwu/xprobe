#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)BPF_FUNC_get_smp_processor_id;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_kernel;
static long (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino,
                                           struct bpf_pidns_info *nsdata,
                                           __u32 size) =
    (void *)BPF_FUNC_get_ns_current_pid_tgid;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

struct xprobe_config {
    __u64 pidns_dev;
    __u64 pidns_ino;
    __u32 target_pid;
    __u32 probe_id;
};

struct xprobe_event {
    __u64 timestamp_ns;
    __u64 sequence;
    __u32 pid;
    __u32 tid;
    __u32 cpu;
    __u32 probe_id;
};

struct xprobe_linux_config {
    __u64 pidns_dev;
    __u64 pidns_ino;
    __u32 target_pid;
    __u32 reserved;
    __s64 syscall_entry_numbers[2];
    __s64 syscall_exit_numbers[2];
};

struct xprobe_linux_event {
    __u64 timestamp_ns;
    __u64 sequence;
    __u64 values[6];
    __u32 pid;
    __u32 tid;
    __u32 cpu;
    __u32 probe_id;
};

struct xprobe_raw_tracepoint_context {
    __u64 arguments[2];
};

struct xprobe_x86_64_registers {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 bp;
    __u64 bx;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 ax;
    __u64 cx;
    __u64 dx;
    __u64 si;
    __u64 di;
    __u64 orig_ax;
    __u64 ip;
    __u64 cs;
    __u64 flags;
    __u64 sp;
    __u64 ss;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xprobe_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sequence SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xprobe_linux_config);
} linux_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} linux_sequence SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} linux_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} linux_events SEC(".maps");

SEC("uprobe")
int xprobe_handle_uprobe(void *context)
{
    __u32 key = 0;
    struct xprobe_config *current = bpf_map_lookup_elem(&config, &key);
    struct bpf_pidns_info nsdata = {};
    struct xprobe_event *event;
    __u64 *counter;

    (void)context;

    if (!current ||
        bpf_get_ns_current_pid_tgid(current->pidns_dev, current->pidns_ino,
                                    &nsdata, sizeof(nsdata)) != 0 ||
        current->target_pid != nsdata.tgid)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        counter = bpf_map_lookup_elem(&dropped, &key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        return 0;
    }

    counter = bpf_map_lookup_elem(&sequence, &key);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->sequence = counter ? __sync_fetch_and_add(counter, 1) + 1 : 0;
    event->pid = nsdata.tgid;
    event->tid = nsdata.pid;
    event->cpu = bpf_get_smp_processor_id();
    event->probe_id = current->probe_id;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __attribute__((always_inline)) int
xprobe_emit_linux_event(__u32 probe_id, const __u64 *values)
{
    __u32 key = 0;
    struct xprobe_linux_config *current =
        bpf_map_lookup_elem(&linux_config, &key);
    struct bpf_pidns_info nsdata = {};
    struct xprobe_linux_event *event;
    __u64 *counter;
    int index;

    if (!current || !current->reserved ||
        bpf_get_ns_current_pid_tgid(current->pidns_dev, current->pidns_ino,
                                    &nsdata, sizeof(nsdata)) != 0 ||
        current->target_pid != nsdata.tgid)
        return 0;

    event = bpf_ringbuf_reserve(&linux_events, sizeof(*event), 0);
    if (!event) {
        counter = bpf_map_lookup_elem(&linux_dropped, &key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        return 0;
    }

    counter = bpf_map_lookup_elem(&linux_sequence, &key);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->sequence = counter ? __sync_fetch_and_add(counter, 1) + 1 : 0;
#pragma unroll
    for (index = 0; index < 6; index++)
        event->values[index] = values ? values[index] : 0;
    event->pid = nsdata.tgid;
    event->tid = nsdata.pid;
    event->cpu = bpf_get_smp_processor_id();
    event->probe_id = probe_id;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

#define XPROBE_TRACEPOINT_PROGRAM(slot)                                      \
    SEC("tracepoint")                                                        \
    int xprobe_handle_tracepoint_##slot(void *context)                       \
    {                                                                        \
        (void)context;                                                       \
        return xprobe_emit_linux_event(slot, 0);                             \
    }

XPROBE_TRACEPOINT_PROGRAM(1)
XPROBE_TRACEPOINT_PROGRAM(2)

#define XPROBE_RAW_TRACEPOINT_PROGRAM(slot)                                  \
    SEC("raw_tracepoint")                                                    \
    int xprobe_handle_raw_tracepoint_##slot(void *context)                   \
    {                                                                        \
        (void)context;                                                       \
        return xprobe_emit_linux_event(slot, 0);                             \
    }

XPROBE_RAW_TRACEPOINT_PROGRAM(1)
XPROBE_RAW_TRACEPOINT_PROGRAM(2)

static __attribute__((always_inline)) __u32
xprobe_syscall_probe_id(const __s64 numbers[2], __s64 syscall_number)
{
    if (numbers[0] == syscall_number)
        return 1;
    if (numbers[1] == syscall_number)
        return 2;
    return 0;
}

static __attribute__((always_inline)) int
xprobe_target_linux_process(struct xprobe_linux_config *current)
{
    struct bpf_pidns_info nsdata = {};

    return current && current->reserved &&
           bpf_get_ns_current_pid_tgid(current->pidns_dev, current->pidns_ino,
                                       &nsdata, sizeof(nsdata)) == 0 &&
           current->target_pid == nsdata.tgid;
}

static __attribute__((always_inline)) void xprobe_count_linux_drop(void)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&linux_dropped, &key);

    if (counter)
        __sync_fetch_and_add(counter, 1);
}

SEC("raw_tracepoint")
int xprobe_handle_syscall_entry(struct xprobe_raw_tracepoint_context *context)
{
    __u32 key = 0;
    struct xprobe_linux_config *current =
        bpf_map_lookup_elem(&linux_config, &key);
    struct xprobe_x86_64_registers registers;
    __u64 values[6];
    __s64 syscall_number = (__s64)context->arguments[1];
    __u32 probe_id;

    if (!xprobe_target_linux_process(current))
        return 0;
    probe_id = xprobe_syscall_probe_id(current->syscall_entry_numbers,
                                       syscall_number);
    if (!probe_id)
        return 0;
    if (bpf_probe_read_kernel(&registers, sizeof(registers),
                              (void *)context->arguments[0]) != 0) {
        xprobe_count_linux_drop();
        return 0;
    }
    values[0] = registers.di;
    values[1] = registers.si;
    values[2] = registers.dx;
    values[3] = registers.r10;
    values[4] = registers.r8;
    values[5] = registers.r9;
    return xprobe_emit_linux_event(probe_id, values);
}

SEC("raw_tracepoint")
int xprobe_handle_syscall_exit(struct xprobe_raw_tracepoint_context *context)
{
    __u32 key = 0;
    struct xprobe_linux_config *current =
        bpf_map_lookup_elem(&linux_config, &key);
    struct xprobe_x86_64_registers registers;
    __u64 values[6] = {};
    __u32 probe_id;

    if (!xprobe_target_linux_process(current))
        return 0;
    if (bpf_probe_read_kernel(&registers, sizeof(registers),
                              (void *)context->arguments[0]) != 0) {
        xprobe_count_linux_drop();
        return 0;
    }
    probe_id = xprobe_syscall_probe_id(current->syscall_exit_numbers,
                                       (__s64)registers.orig_ax);
    if (!probe_id)
        return 0;
    values[0] = context->arguments[1];
    return xprobe_emit_linux_event(probe_id, values);
}

char _license[] SEC("license") = "GPL";
