#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)BPF_FUNC_get_smp_processor_id;
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

char _license[] SEC("license") = "GPL";
