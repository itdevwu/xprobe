#include "xprobe/cupti_agent.h"

unsigned int xprobe_cupti_agent_abi_version(void)
{
    return XPROBE_CUPTI_AGENT_ABI_VERSION;
}

#ifndef XPROBE_HAS_CUPTI

int xprobe_cupti_agent_initialize(void)
{
    return XPROBE_CUPTI_AGENT_UNAVAILABLE;
}

int xprobe_cupti_agent_start(const char *socket_path, uint64_t record_capacity)
{
    (void)socket_path;
    (void)record_capacity;
    return XPROBE_CUPTI_AGENT_UNAVAILABLE;
}

int InitializeInjection(void)
{
    return 0;
}

int xprobe_cupti_agent_status(void)
{
    return XPROBE_CUPTI_AGENT_UNAVAILABLE;
}

unsigned int xprobe_cupti_agent_last_cupti_result(void)
{
    return 0U;
}

int xprobe_cupti_agent_flush(void)
{
    return XPROBE_CUPTI_AGENT_UNAVAILABLE;
}

#else

#include <cupti.h>
#include <cupti_activity.h>
#include <cupti_callbacks.h>
#include <cupti_driver_cbid.h>
#include <cupti_runtime_cbid.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define XPROBE_CUPTI_DEFAULT_RECORD_CAPACITY 100000U
#define XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE (8U * 1024U * 1024U)
#define XPROBE_CUPTI_CLOCK_MARGIN_NS 1000000000U
#define XPROBE_CUPTI_CORRELATION_CLOCK_MARGIN_NS 1000000U

_Static_assert(sizeof(struct xprobe_cupti_output_header) == 80U,
               "unexpected CUPTI output header layout");
_Static_assert(sizeof(struct xprobe_cupti_record) == 200U,
               "unexpected CUPTI record layout");
_Static_assert(sizeof(struct xprobe_cupti_filter) == 144U,
               "unexpected CUPTI filter layout");
_Static_assert(sizeof(struct xprobe_cupti_control_request) == 312U,
               "unexpected CUPTI control request layout");

static struct xprobe_cupti_record *records;
static _Atomic unsigned char *record_ready;
static uint64_t record_capacity;
static _Atomic uint64_t record_count;
static _Atomic uint64_t committed_record_count;
static _Atomic uint64_t agent_dropped_records;
static _Atomic uint64_t cupti_dropped_records;
static _Atomic uint64_t unknown_records;
static _Atomic uint64_t requested_buffers;
static _Atomic uint64_t completed_buffers;
static _Atomic int agent_status = XPROBE_CUPTI_AGENT_UNAVAILABLE;
static _Atomic int capture_state = XPROBE_CUPTI_CAPTURE_IDLE;
static _Atomic int stop_reason = XPROBE_CUPTI_STOP_NONE;
static _Atomic unsigned int last_cupti_result;
static _Atomic int output_written;
static uint32_t runtime_cupti_version;
static int64_t activity_timestamp_offset_ns;
static uint64_t capture_start_timestamp_ns;
static _Atomic int clock_alignment_warning_emitted;
static CUpti_SubscriberHandle subscriber;
static int subscriber_active;
static int agent_initialized;
static uint32_t enabled_activity_mask;
static char output_path[PATH_MAX];
static char snapshot_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t snapshot_thread;
static _Atomic int snapshot_thread_stop;
static _Atomic int snapshot_listener = -1;
static int snapshot_thread_started;
static struct xprobe_cupti_filter capture_filters[XPROBE_CUPTI_FILTER_COUNT];
static _Atomic int capture_filter_enabled;
#define XPROBE_CUPTI_ACTIVITY_KERNEL (1U << 0)
#define XPROBE_CUPTI_ACTIVITY_MEMCPY (1U << 1)
#define XPROBE_CUPTI_ACTIVITY_MEMSET (1U << 2)

static int shutdown_agent(void);
static int activate_capture(void);

static int allocate_capture(uint64_t capacity)
{
    struct xprobe_cupti_record *new_records;
    _Atomic unsigned char *new_ready;

    if (capacity == 0U || capacity > SIZE_MAX / sizeof(*records) ||
        capacity > SIZE_MAX / sizeof(*record_ready)) {
        fprintf(stderr, "xprobe CUPTI: invalid record capacity %llu\n",
                (unsigned long long)capacity);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    new_records = calloc((size_t)capacity, sizeof(*new_records));
    new_ready = malloc((size_t)capacity * sizeof(*new_ready));
    if (new_records == NULL || new_ready == NULL) {
        fprintf(stderr, "xprobe CUPTI: failed to allocate %llu capture records\n",
                (unsigned long long)capacity);
        free(new_records);
        free(new_ready);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    for (uint64_t index = 0U; index < capacity; ++index) {
        atomic_init(&new_ready[index], 0U);
    }
    free(records);
    free(record_ready);
    records = new_records;
    record_ready = new_ready;
    record_capacity = capacity;
    return XPROBE_CUPTI_AGENT_READY;
}

static void reset_capture(void)
{
    uint64_t index;

    for (index = 0U; index < record_capacity; ++index) {
        atomic_store_explicit(&record_ready[index], 0U, memory_order_relaxed);
    }
    atomic_store_explicit(&record_count, 0U, memory_order_relaxed);
    atomic_store_explicit(&committed_record_count, 0U, memory_order_relaxed);
    atomic_store_explicit(&agent_dropped_records, 0U, memory_order_relaxed);
    atomic_store_explicit(&cupti_dropped_records, 0U, memory_order_relaxed);
    atomic_store_explicit(&unknown_records, 0U, memory_order_relaxed);
    atomic_store_explicit(&requested_buffers, 0U, memory_order_relaxed);
    atomic_store_explicit(&completed_buffers, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_cupti_result, 0U, memory_order_relaxed);
    atomic_store_explicit(&output_written, 0, memory_order_relaxed);
    atomic_store_explicit(&clock_alignment_warning_emitted, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_IDLE,
                          memory_order_relaxed);
    atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_NONE,
                          memory_order_relaxed);
}

static void remember_cupti_error(CUptiResult result)
{
    atomic_store_explicit(&last_cupti_result, (unsigned int)result,
                          memory_order_relaxed);
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_CUPTI_ERROR,
                          memory_order_relaxed);
    atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_FAILED,
                          memory_order_relaxed);
    atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_CUPTI_ERROR,
                          memory_order_relaxed);
}

static void remember_output_error(void)
{
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                          memory_order_relaxed);
    atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_FAILED,
                          memory_order_relaxed);
    atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_OUTPUT_ERROR,
                          memory_order_relaxed);
}

static void report_cupti_error(const char *operation, CUptiResult result)
{
    const char *message = NULL;
    CUptiResult string_result;

    remember_cupti_error(result);
    string_result = cuptiGetResultString(result, &message);
    if (string_result == CUPTI_SUCCESS && message != NULL) {
        fprintf(stderr, "xprobe CUPTI: %s failed: %s\n", operation, message);
    } else {
        fprintf(stderr, "xprobe CUPTI: %s failed with code %u\n", operation,
                (unsigned int)result);
    }
}

static uint32_t current_tid(void)
{
    return (uint32_t)syscall(SYS_gettid);
}

static int monotonic_timestamp_ns(uint64_t *timestamp_ns)
{
    struct timespec timestamp;

    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        fprintf(stderr, "xprobe CUPTI: clock_gettime failed: %s\n", strerror(errno));
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    *timestamp_ns = (uint64_t)timestamp.tv_sec * 1000000000U +
                    (uint64_t)timestamp.tv_nsec;
    return XPROBE_CUPTI_AGENT_READY;
}

#if CUPTI_API_VERSION >= 130000
static uint64_t activity_timestamp(void)
{
    uint64_t timestamp_ns = 0U;

    (void)monotonic_timestamp_ns(&timestamp_ns);
    return timestamp_ns;
}
#else

static int calibrate_activity_timestamp(void)
{
    uint64_t host_before;
    uint64_t host_after;
    uint64_t host_midpoint;
    uint64_t cupti_timestamp;
    uint64_t difference;
    CUptiResult result;

    if (monotonic_timestamp_ns(&host_before) != XPROBE_CUPTI_AGENT_READY) {
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    result = cuptiGetTimestamp(&cupti_timestamp);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiGetTimestamp", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (monotonic_timestamp_ns(&host_after) != XPROBE_CUPTI_AGENT_READY) {
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    host_midpoint = host_before + (host_after - host_before) / 2U;
    if (cupti_timestamp >= host_midpoint) {
        difference = cupti_timestamp - host_midpoint;
        if (difference > (uint64_t)INT64_MAX) {
            fprintf(stderr, "xprobe CUPTI: activity clock offset exceeds int64\n");
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        activity_timestamp_offset_ns = -(int64_t)difference;
    } else {
        difference = host_midpoint - cupti_timestamp;
        if (difference > (uint64_t)INT64_MAX) {
            fprintf(stderr, "xprobe CUPTI: activity clock offset exceeds int64\n");
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        activity_timestamp_offset_ns = (int64_t)difference;
    }
    return XPROBE_CUPTI_AGENT_READY;
}
#endif

static uint64_t normalize_activity_timestamp(uint64_t timestamp_ns)
{
    if (activity_timestamp_offset_ns < 0) {
        return timestamp_ns - (uint64_t)(-activity_timestamp_offset_ns);
    }
    return timestamp_ns + (uint64_t)activity_timestamp_offset_ns;
}

static void copy_name(char destination[XPROBE_CUPTI_NAME_LENGTH],
                      const char *source)
{
    size_t index;

    if (source == NULL) {
        destination[0] = '\0';
        return;
    }
    for (index = 0U; index + 1U < XPROBE_CUPTI_NAME_LENGTH && source[index] != '\0';
         ++index) {
        destination[index] = source[index];
    }
    destination[index] = '\0';
}

static size_t bounded_name_length(const char *name)
{
    size_t length = 0U;

    if (name == NULL) {
        return 0U;
    }
    while (length < XPROBE_CUPTI_NAME_LENGTH && name[length] != '\0') {
        ++length;
    }
    return length;
}

static int name_matches(const struct xprobe_cupti_filter *filter,
                        const char *record_name)
{
    size_t filter_length;
    size_t record_length;

    if (filter->name_match == XPROBE_CUPTI_NAME_ANY) {
        return 1;
    }
    if (record_name == NULL) {
        record_name = "";
    }
    filter_length = bounded_name_length(filter->name);
    record_length = bounded_name_length(record_name);
    if (filter_length == XPROBE_CUPTI_NAME_LENGTH ||
        record_length == XPROBE_CUPTI_NAME_LENGTH) {
        return 0;
    }
    if (filter->name_match == XPROBE_CUPTI_NAME_EXACT) {
        return filter_length == record_length &&
               memcmp(filter->name, record_name, filter_length) == 0;
    }
    if (filter->name_match == XPROBE_CUPTI_NAME_PREFIX) {
        return filter_length <= record_length &&
               memcmp(filter->name, record_name, filter_length) == 0;
    }
    if (filter->name_match == XPROBE_CUPTI_NAME_SUFFIX) {
        return filter_length <= record_length &&
               memcmp(filter->name, record_name + record_length - filter_length,
                      filter_length) == 0;
    }
    if (filter->name_match == XPROBE_CUPTI_NAME_CONTAINS) {
        if (filter_length == 0U) {
            return 1;
        }
        for (size_t offset = 0U; offset + filter_length <= record_length;
             ++offset) {
            if (memcmp(filter->name, record_name + offset, filter_length) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t semantic_memcpy_kind(uint32_t cupti_kind)
{
    switch (cupti_kind) {
    case 1U:
    case 3U:
        return 1U;
    case 2U:
    case 4U:
        return 2U;
    case 5U:
    case 6U:
    case 7U:
    case 8U:
        return 3U;
    case 9U:
        return 4U;
    case 10U:
        return 5U;
    default:
        return 0U;
    }
}

static int filter_matches_values(const struct xprobe_cupti_filter *filter,
                                 uint32_t record_kind, uint32_t api_domain,
                                 uint32_t memcpy_kind, const char *name)
{
    if (filter->record_kind == 0U || filter->record_kind != record_kind) {
        return 0;
    }
    if (filter->api_domain != 0U && filter->api_domain != api_domain) {
        return 0;
    }
    if (filter->memcpy_kind != 0U && filter->memcpy_kind != memcpy_kind) {
        return 0;
    }
    return name_matches(filter, name);
}

static int record_matches_filter(const struct xprobe_cupti_record *record,
                                 const struct xprobe_cupti_filter *filter)
{
    return filter_matches_values(filter, record->kind, record->callback_domain,
                                 semantic_memcpy_kind(record->grid_z),
                                 record->name);
}

static int values_match_capture(uint32_t first_kind, uint32_t second_kind,
                                uint32_t api_domain, uint32_t memcpy_kind,
                                const char *name)
{
    if (atomic_load_explicit(&capture_filter_enabled, memory_order_relaxed) == 0) {
        return 1;
    }
    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        const struct xprobe_cupti_filter *filter = &capture_filters[index];

        if (filter_matches_values(filter, first_kind, api_domain, memcpy_kind,
                                  name) != 0 ||
            (second_kind != 0U &&
             filter_matches_values(filter, second_kind, api_domain, memcpy_kind,
                                   name) != 0)) {
            return 1;
        }
    }
    return 0;
}

static int capture_filter_matches(const struct xprobe_cupti_record *record)
{
    if (atomic_load_explicit(&capture_filter_enabled, memory_order_relaxed) == 0) {
        return 1;
    }
    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        if (record_matches_filter(record, &capture_filters[index]) != 0) {
            return 1;
        }
    }
    return 0;
}

static void enqueue_record(const struct xprobe_cupti_record *record)
{
    uint64_t index;
    uint64_t committed;

    if (atomic_load_explicit(&capture_state, memory_order_relaxed) !=
        XPROBE_CUPTI_CAPTURE_ACTIVE) {
        return;
    }
    if (capture_filter_matches(record) == 0) {
        return;
    }
    index = atomic_fetch_add_explicit(&record_count, 1U, memory_order_relaxed);
    if (index >= record_capacity) {
        atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_RECORD_LIMIT,
                              memory_order_relaxed);
        atomic_store_explicit(&capture_state,
                              XPROBE_CUPTI_CAPTURE_LIMIT_REACHED,
                              memory_order_release);
        return;
    }
    records[index] = *record;
    atomic_store_explicit(&record_ready[index], 1U, memory_order_release);

    committed = atomic_load_explicit(&committed_record_count, memory_order_acquire);
    while (committed < record_capacity &&
           atomic_load_explicit(&record_ready[committed], memory_order_acquire) != 0U) {
        if (atomic_compare_exchange_weak_explicit(
                &committed_record_count, &committed, committed + 1U,
                memory_order_release, memory_order_acquire)) {
            ++committed;
        }
    }
}

static void initialize_record(struct xprobe_cupti_record *record, uint32_t kind,
                              uint64_t timestamp_ns)
{
    memset(record, 0, sizeof(*record));
    record->timestamp_ns = timestamp_ns;
    record->kind = kind;
    record->pid = (uint32_t)getpid();
    record->tid = current_tid();
    record->device_id = XPROBE_CUPTI_VALUE_UNKNOWN;
    record->context_id = XPROBE_CUPTI_VALUE_UNKNOWN;
    record->stream_id = XPROBE_CUPTI_VALUE_UNKNOWN;
}

static void enqueue_api_record(const CUpti_CallbackData *data,
                               CUpti_CallbackDomain domain,
                               CUpti_CallbackId callback_id, uint32_t kind,
                               uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, timestamp_ns);
    record.context_id = data->contextUid;
    record.correlation_id = data->correlationId;
    record.runtime_correlation_id = data->correlationId;
    record.callback_domain = (uint32_t)domain;
    record.callback_id = callback_id;
    copy_name(record.name, data->functionName);
    enqueue_record(&record);
}

static void CUPTIAPI api_callback(void *userdata, CUpti_CallbackDomain domain,
                                  CUpti_CallbackId callback_id,
                                  const void *callback_data)
{
    const CUpti_CallbackData *data = callback_data;
    uint32_t kind;
    uint64_t timestamp_ns;

    (void)userdata;
    if (domain != CUPTI_CB_DOMAIN_RUNTIME_API &&
        domain != CUPTI_CB_DOMAIN_DRIVER_API) {
        return;
    }
    kind = data->callbackSite == CUPTI_API_ENTER ? XPROBE_CUPTI_CUDA_API_ENTRY
                                                : XPROBE_CUPTI_CUDA_API_EXIT;
    if (values_match_capture(kind, 0U, (uint32_t)domain, 0U,
                             data->functionName) == 0) {
        return;
    }

    if (monotonic_timestamp_ns(&timestamp_ns) != XPROBE_CUPTI_AGENT_READY) {
        return;
    }
    enqueue_api_record(data, domain, callback_id, kind, timestamp_ns);
}

static void CUPTIAPI activity_buffer_requested(uint8_t **buffer, size_t *size,
                                               size_t *maximum_records)
{
    void *memory = NULL;
    int result = posix_memalign(&memory, 8U, XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE);

    if (result != 0) {
        *buffer = NULL;
        *size = 0U;
        remember_output_error();
        return;
    }
    *buffer = memory;
    *size = XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE;
    *maximum_records = 0U;
    atomic_fetch_add_explicit(&requested_buffers, 1U, memory_order_relaxed);
}

static void enqueue_kernel_record(uint32_t device_id, uint32_t context_id,
                                  uint32_t stream_id, uint32_t correlation_id,
                                  int32_t grid_x, int32_t grid_y, int32_t grid_z,
                                  int32_t block_x, int32_t block_y, int32_t block_z,
                                  const char *name, uint32_t kind,
                                  uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, normalize_activity_timestamp(timestamp_ns));
    record.device_id = device_id;
    record.context_id = context_id;
    record.stream_id = stream_id;
    record.correlation_id = correlation_id;
    record.grid_x = (uint32_t)grid_x;
    record.grid_y = (uint32_t)grid_y;
    record.grid_z = (uint32_t)grid_z;
    record.block_x = (uint32_t)block_x;
    record.block_y = (uint32_t)block_y;
    record.block_z = (uint32_t)block_z;
    copy_name(record.name, name);
    enqueue_record(&record);
}

static int activity_started_during_capture(uint64_t timestamp_ns)
{
    return timestamp_ns != 0U &&
           normalize_activity_timestamp(timestamp_ns) >=
               capture_start_timestamp_ns;
}

#define ENQUEUE_KERNEL_RECORDS(kernel)                                             \
    do {                                                                           \
        if (activity_started_during_capture((kernel)->start) == 0) {               \
            return;                                                                \
        }                                                                          \
        if (values_match_capture(XPROBE_CUPTI_GPU_KERNEL_START,                    \
                                 XPROBE_CUPTI_GPU_KERNEL_END, 0U, 0U,               \
                                 (kernel)->name) == 0) {                             \
            return;                                                                \
        }                                                                          \
        enqueue_kernel_record(                                                     \
            (kernel)->deviceId, (kernel)->contextId, (kernel)->streamId,           \
            (kernel)->correlationId, (kernel)->gridX, (kernel)->gridY,             \
            (kernel)->gridZ, (kernel)->blockX, (kernel)->blockY,                   \
            (kernel)->blockZ, (kernel)->name, XPROBE_CUPTI_GPU_KERNEL_START,       \
            (kernel)->start);                                                       \
        enqueue_kernel_record(                                                     \
            (kernel)->deviceId, (kernel)->contextId, (kernel)->streamId,           \
            (kernel)->correlationId, (kernel)->gridX, (kernel)->gridY,             \
            (kernel)->gridZ, (kernel)->blockX, (kernel)->blockY,                   \
            (kernel)->blockZ, (kernel)->name, XPROBE_CUPTI_GPU_KERNEL_END,         \
            (kernel)->end);                                                         \
    } while (0)

static void enqueue_kernel_activity(const CUpti_Activity *activity)
{
#if CUPTI_API_VERSION < 130000
    const CUpti_ActivityKernel9 *kernel =
        (const CUpti_ActivityKernel9 *)activity;

    ENQUEUE_KERNEL_RECORDS(kernel);
#else
    if (runtime_cupti_version >= 130300U) {
        const CUpti_ActivityKernel12 *kernel =
            (const CUpti_ActivityKernel12 *)activity;
        ENQUEUE_KERNEL_RECORDS(kernel);
    } else if (runtime_cupti_version >= 130200U) {
        const CUpti_ActivityKernel11 *kernel =
            (const CUpti_ActivityKernel11 *)activity;
        ENQUEUE_KERNEL_RECORDS(kernel);
    } else {
        const CUpti_ActivityKernel10 *kernel =
            (const CUpti_ActivityKernel10 *)activity;
        ENQUEUE_KERNEL_RECORDS(kernel);
    }
#endif
}

#undef ENQUEUE_KERNEL_RECORDS

static void set_transfer_bytes(struct xprobe_cupti_record *record, uint64_t bytes)
{
    record->grid_x = (uint32_t)bytes;
    record->grid_y = (uint32_t)(bytes >> 32U);
}

static void enqueue_memcpy_record(const CUpti_ActivityMemcpy6 *memcpy_record,
                                  uint32_t kind, uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, normalize_activity_timestamp(timestamp_ns));
    record.device_id = memcpy_record->deviceId;
    record.context_id = memcpy_record->contextId;
    record.stream_id = memcpy_record->streamId;
    record.correlation_id = memcpy_record->correlationId;
    record.runtime_correlation_id = memcpy_record->runtimeCorrelationId;
    set_transfer_bytes(&record, memcpy_record->bytes);
    record.grid_z = (uint32_t)memcpy_record->copyKind;
    enqueue_record(&record);
}

static void enqueue_memset_record(const CUpti_ActivityMemset4 *memset_record,
                                  uint32_t kind, uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, normalize_activity_timestamp(timestamp_ns));
    record.device_id = memset_record->deviceId;
    record.context_id = memset_record->contextId;
    record.stream_id = memset_record->streamId;
    record.correlation_id = memset_record->correlationId;
    set_transfer_bytes(&record, memset_record->bytes);
    record.block_x = memset_record->value;
    enqueue_record(&record);
}

static void CUPTIAPI activity_buffer_completed(CUcontext context, uint32_t stream_id,
                                               uint8_t *buffer, size_t size,
                                               size_t valid_size)
{
    CUpti_Activity *activity = NULL;
    CUptiResult result;

    (void)context;
    (void)stream_id;
    (void)size;
    for (;;) {
        result = cuptiActivityGetNextRecord(buffer, valid_size, &activity);
        if (result == CUPTI_ERROR_MAX_LIMIT_REACHED) {
            break;
        }
        if (result != CUPTI_SUCCESS) {
            remember_cupti_error(result);
            break;
        }
        if (atomic_load_explicit(&capture_state, memory_order_relaxed) !=
            XPROBE_CUPTI_CAPTURE_ACTIVE) {
            continue;
        }
        if (activity->kind == CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
            enqueue_kernel_activity(activity);
        } else if (activity->kind == CUPTI_ACTIVITY_KIND_MEMCPY) {
            const CUpti_ActivityMemcpy6 *memcpy_record =
                (const CUpti_ActivityMemcpy6 *)activity;
            if (activity_started_during_capture(memcpy_record->start) == 0) {
                continue;
            }
            if (values_match_capture(
                    XPROBE_CUPTI_GPU_MEMCPY_START,
                    XPROBE_CUPTI_GPU_MEMCPY_END, 0U,
                    semantic_memcpy_kind((uint32_t)memcpy_record->copyKind),
                    NULL) == 0) {
                continue;
            }
            enqueue_memcpy_record(memcpy_record, XPROBE_CUPTI_GPU_MEMCPY_START,
                                  memcpy_record->start);
            enqueue_memcpy_record(memcpy_record, XPROBE_CUPTI_GPU_MEMCPY_END,
                                  memcpy_record->end);
        } else if (activity->kind == CUPTI_ACTIVITY_KIND_MEMSET) {
            const CUpti_ActivityMemset4 *memset_record =
                (const CUpti_ActivityMemset4 *)activity;
            if (activity_started_during_capture(memset_record->start) == 0) {
                continue;
            }
            if (values_match_capture(XPROBE_CUPTI_GPU_MEMSET_START,
                                     XPROBE_CUPTI_GPU_MEMSET_END, 0U, 0U,
                                     NULL) == 0) {
                continue;
            }
            enqueue_memset_record(memset_record, XPROBE_CUPTI_GPU_MEMSET_START,
                                  memset_record->start);
            enqueue_memset_record(memset_record, XPROBE_CUPTI_GPU_MEMSET_END,
                                  memset_record->end);
        } else {
            atomic_fetch_add_explicit(&unknown_records, 1U, memory_order_relaxed);
        }
    }

    free(buffer);
    atomic_fetch_add_explicit(&completed_buffers, 1U, memory_order_release);
}

static int wait_for_activity_buffers(uint64_t completed_before_flush,
                                     int allow_empty_flush)
{
    struct timespec now;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    uint64_t deadline_ns;
    uint64_t empty_deadline_ns;
    uint64_t quiet_since_ns = 0U;
    uint64_t previous_completed = 0U;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fprintf(stderr, "xprobe CUPTI: clock_gettime failed: %s\n", strerror(errno));
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    deadline_ns = (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec +
                  5000000000U;
    empty_deadline_ns = (uint64_t)now.tv_sec * 1000000000U +
                        (uint64_t)now.tv_nsec + 100000000U;

    for (;;) {
        uint64_t completed =
            atomic_load_explicit(&completed_buffers, memory_order_acquire);
        uint64_t now_ns;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            fprintf(stderr, "xprobe CUPTI: clock_gettime failed: %s\n",
                    strerror(errno));
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        now_ns = (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec;
        if (completed > completed_before_flush) {
            if (completed != previous_completed) {
                quiet_since_ns = now_ns;
            } else if (now_ns - quiet_since_ns >= 100000000U) {
                return XPROBE_CUPTI_AGENT_READY;
            }
        } else {
            quiet_since_ns = 0U;
        }
        previous_completed = completed;

        if (allow_empty_flush != 0 && completed == completed_before_flush &&
            now_ns >= empty_deadline_ns) {
            return XPROBE_CUPTI_AGENT_READY;
        }

        if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
            fprintf(stderr, "xprobe CUPTI: nanosleep failed: %s\n", strerror(errno));
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        if (now_ns >= deadline_ns) {
            fprintf(stderr,
                    "xprobe CUPTI: timed out waiting for activity buffers "
                    "(%llu/%llu completed)\n",
                    (unsigned long long)atomic_load_explicit(
                        &completed_buffers, memory_order_relaxed),
                    (unsigned long long)atomic_load_explicit(
                        &requested_buffers, memory_order_relaxed));
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
    }
}

static int write_all(int descriptor, const void *data, size_t size)
{
    const uint8_t *cursor = data;

    while (size > 0U) {
        ssize_t written = write(descriptor, cursor, size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

static int send_all(int descriptor, const void *data, size_t size)
{
    const uint8_t *cursor = data;

    while (size > 0U) {
        ssize_t written = send(descriptor, cursor, size, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

static int receive_all(int descriptor, void *data, size_t size)
{
    uint8_t *cursor = data;

    while (size > 0U) {
        ssize_t received = recv(descriptor, cursor, size, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += (size_t)received;
        size -= (size_t)received;
    }
    return 0;
}

static int activity_timestamps_are_host_monotonic(uint64_t available)
{
    uint64_t capture_end_timestamp_ns;
    const struct xprobe_cupti_record *first_kernel = NULL;

    if (monotonic_timestamp_ns(&capture_end_timestamp_ns) !=
        XPROBE_CUPTI_AGENT_READY) {
        return 0;
    }
    for (uint64_t index = 0U; index < available; ++index) {
        const struct xprobe_cupti_record *record = &records[index];
        uint64_t timestamp_ns = record->timestamp_ns;
        int is_activity = record->kind >= XPROBE_CUPTI_GPU_KERNEL_START &&
                          record->kind <= XPROBE_CUPTI_GPU_MEMSET_END;

        if (is_activity == 0) {
            continue;
        }
        if ((timestamp_ns < capture_start_timestamp_ns &&
             capture_start_timestamp_ns - timestamp_ns >
                 XPROBE_CUPTI_CLOCK_MARGIN_NS) ||
            (timestamp_ns > capture_end_timestamp_ns &&
             timestamp_ns - capture_end_timestamp_ns >
                 XPROBE_CUPTI_CLOCK_MARGIN_NS)) {
            goto unaligned;
        }
        if (first_kernel == NULL &&
            record->kind == XPROBE_CUPTI_GPU_KERNEL_START) {
            first_kernel = record;
        }
    }
    if (first_kernel != NULL) {
        for (uint64_t index = 0U; index < available; ++index) {
            const struct xprobe_cupti_record *record = &records[index];

            if (record->kind == XPROBE_CUPTI_CUDA_API_ENTRY &&
                record->correlation_id == first_kernel->correlation_id) {
                if (first_kernel->timestamp_ns < record->timestamp_ns &&
                    record->timestamp_ns - first_kernel->timestamp_ns >
                        XPROBE_CUPTI_CORRELATION_CLOCK_MARGIN_NS) {
                    goto unaligned;
                }
                break;
            }
        }
    }
    return 1;

unaligned:
    if (atomic_exchange_explicit(&clock_alignment_warning_emitted, 1,
                                 memory_order_relaxed) == 0) {
        fprintf(stderr,
                "xprobe CUPTI: activity timestamps are not aligned to "
                "CLOCK_MONOTONIC\n");
    }
    return 0;
}

static void initialize_output_header(struct xprobe_cupti_output_header *header,
                                     uint64_t available)
{
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, XPROBE_CUPTI_OUTPUT_MAGIC, sizeof(header->magic));
    header->abi_version = XPROBE_CUPTI_AGENT_ABI_VERSION;
    header->header_size = sizeof(*header);
    header->record_size = sizeof(records[0]);
    header->feature_flags = XPROBE_CUPTI_FEATURE_TRANSFER_RECORDS;
    if (activity_timestamps_are_host_monotonic(available) != 0) {
        header->feature_flags |= XPROBE_CUPTI_FEATURE_HOST_MONOTONIC_TIMESTAMPS;
    }
    header->capture_state =
        (uint32_t)atomic_load_explicit(&capture_state, memory_order_acquire);
    header->stop_reason =
        (uint32_t)atomic_load_explicit(&stop_reason, memory_order_relaxed);
    header->record_count = available;
    header->record_capacity = record_capacity;
    header->observed_records =
        atomic_load_explicit(&record_count, memory_order_relaxed);
    header->agent_dropped_records =
        atomic_load_explicit(&agent_dropped_records, memory_order_relaxed);
    header->cupti_dropped_records =
        atomic_load_explicit(&cupti_dropped_records, memory_order_relaxed);
    header->unknown_records =
        atomic_load_explicit(&unknown_records, memory_order_relaxed);
}

static int write_capture(int descriptor, int is_socket)
{
    struct xprobe_cupti_output_header header;
    uint64_t available =
        atomic_load_explicit(&committed_record_count, memory_order_acquire);
    int (*write_function)(int, const void *, size_t) =
        is_socket != 0 ? send_all : write_all;
    int result;

    initialize_output_header(&header, available);
    result = write_function(descriptor, &header, sizeof(header));
    if (result == 0) {
        result = write_function(descriptor, records,
                                available * sizeof(records[0]));
    }
    return result;
}

static int write_output(void)
{
    int descriptor;
    int result;

    descriptor = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        fprintf(stderr, "xprobe CUPTI: failed to open %s: %s\n", output_path,
                strerror(errno));
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    result = write_capture(descriptor, 0);
    if (close(descriptor) != 0 && result == 0) {
        result = -1;
    }
    if (result != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to write %s: %s\n", output_path,
                strerror(errno));
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    atomic_store_explicit(&output_written, 1, memory_order_relaxed);
    return XPROBE_CUPTI_AGENT_READY;
}

static int flush_activity_buffers(int allow_empty_flush)
{
    CUptiResult result;
    size_t dropped = 0U;
    uint64_t completed_before_flush =
        atomic_load_explicit(&completed_buffers, memory_order_acquire);

    result = cuptiActivityFlushAll(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityFlushAll", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (wait_for_activity_buffers(completed_before_flush, allow_empty_flush) !=
        XPROBE_CUPTI_AGENT_READY) {
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_CUPTI_ERROR,
                              memory_order_relaxed);
        atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_FAILED,
                              memory_order_relaxed);
        atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_CUPTI_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    result = cuptiActivityGetNumDroppedRecords(NULL, 0U, &dropped);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityGetNumDroppedRecords", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    atomic_fetch_add_explicit(&cupti_dropped_records, dropped,
                              memory_order_relaxed);
    return xprobe_cupti_agent_status();
}

static int valid_filter(const struct xprobe_cupti_filter *filter)
{
    if (filter->record_kind > XPROBE_CUPTI_GPU_MEMSET_END ||
        filter->api_domain > CUPTI_CB_DOMAIN_RUNTIME_API ||
        filter->memcpy_kind > 5U ||
        filter->name_match > XPROBE_CUPTI_NAME_CONTAINS) {
        return 0;
    }
    return filter->name_match == XPROBE_CUPTI_NAME_ANY ||
           bounded_name_length(filter->name) < XPROBE_CUPTI_NAME_LENGTH;
}

static int arm_capture(const struct xprobe_cupti_control_request *request)
{
    int status;

    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        if (valid_filter(&request->filters[index]) == 0) {
            fprintf(stderr, "xprobe CUPTI: invalid capture filter\n");
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
    }
    if (subscriber_active != 0 || enabled_activity_mask != 0U) {
        status = shutdown_agent();
        if (status != XPROBE_CUPTI_AGENT_READY) {
            return status;
        }
    }
    if (allocate_capture(request->record_capacity) != XPROBE_CUPTI_AGENT_READY) {
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    reset_capture();
    memcpy(capture_filters, request->filters, sizeof(capture_filters));
    atomic_store_explicit(&capture_filter_enabled, 1, memory_order_release);
    return activate_capture();
}

static int stop_capture(void)
{
    int status = XPROBE_CUPTI_AGENT_READY;

    if (enabled_activity_mask != 0U) {
        status = flush_activity_buffers(1);
    }
    if (status == XPROBE_CUPTI_AGENT_READY &&
        (subscriber_active != 0 || enabled_activity_mask != 0U)) {
        status = shutdown_agent();
    }
    if (status == XPROBE_CUPTI_AGENT_READY &&
        atomic_load_explicit(&capture_state, memory_order_acquire) ==
            XPROBE_CUPTI_CAPTURE_ACTIVE) {
        atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_STOPPED,
                              memory_order_release);
        atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_REQUESTED,
                              memory_order_relaxed);
    }
    return status;
}

static void *serve_snapshots(void *unused)
{
    (void)unused;
    while (atomic_load_explicit(&snapshot_thread_stop, memory_order_acquire) == 0) {
        struct pollfd poll_descriptor = {
            .fd = atomic_load_explicit(&snapshot_listener, memory_order_acquire),
            .events = POLLIN,
        };
        int poll_result = poll(&poll_descriptor, 1U, 100);
        int client;
        struct xprobe_cupti_control_request request;
        int close_requested = 0;

        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result < 0) {
            if (atomic_load_explicit(&snapshot_thread_stop, memory_order_acquire) == 0) {
                fprintf(stderr, "xprobe CUPTI: snapshot poll failed: %s\n",
                        strerror(errno));
            }
            break;
        }
        if (poll_result == 0 || (poll_descriptor.revents & POLLIN) == 0) {
            continue;
        }
        client = accept4(poll_descriptor.fd, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) {
            continue;
        }
        if (client < 0) {
            if (atomic_load_explicit(&snapshot_thread_stop, memory_order_acquire) == 0) {
                fprintf(stderr, "xprobe CUPTI: snapshot accept failed: %s\n",
                        strerror(errno));
            }
            continue;
        }

        if (receive_all(client, &request, sizeof(request)) != 0 ||
            memcmp(request.magic, XPROBE_CUPTI_CONTROL_MAGIC,
                   sizeof(request.magic)) != 0 ||
            request.version != XPROBE_CUPTI_CONTROL_VERSION ||
            (request.command < XPROBE_CUPTI_CONTROL_ARM ||
             request.command > XPROBE_CUPTI_CONTROL_CLOSE)) {
            fprintf(stderr, "xprobe CUPTI: invalid snapshot control request\n");
        } else if (pthread_mutex_lock(&flush_mutex) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to lock snapshot flush mutex\n");
        } else {
            int command_status = XPROBE_CUPTI_AGENT_READY;

            if (request.command == XPROBE_CUPTI_CONTROL_ARM) {
                command_status = arm_capture(&request);
            } else if (request.command == XPROBE_CUPTI_CONTROL_SNAPSHOT) {
                if (atomic_load_explicit(&capture_state, memory_order_acquire) ==
                    XPROBE_CUPTI_CAPTURE_ACTIVE) {
                    command_status = flush_activity_buffers(1);
                }
            } else {
                command_status = stop_capture();
                close_requested =
                    request.command == XPROBE_CUPTI_CONTROL_CLOSE;
            }
            (void)command_status;
            if (write_capture(client, 1) != 0) {
                fprintf(stderr, "xprobe CUPTI: failed to send snapshot: %s\n",
                        strerror(errno));
            }
            if (pthread_mutex_unlock(&flush_mutex) != 0) {
                fprintf(stderr, "xprobe CUPTI: failed to unlock snapshot flush mutex\n");
            }
        }
        if (close(client) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to close snapshot client: %s\n",
                    strerror(errno));
        }
        if (close_requested != 0) {
            atomic_store_explicit(&snapshot_thread_stop, 1, memory_order_release);
        }
    }
    {
        int descriptor = atomic_exchange_explicit(&snapshot_listener, -1,
                                                  memory_order_acq_rel);
        if (descriptor >= 0) {
            (void)shutdown(descriptor, SHUT_RDWR);
            (void)close(descriptor);
        }
    }
    if (snapshot_socket_path[0] != '\0') {
        (void)unlink(snapshot_socket_path);
    }
    return NULL;
}

static int start_snapshot_server(void)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int descriptor;
    int thread_result;

    if (snapshot_socket_path[0] == '\0') {
        return XPROBE_CUPTI_AGENT_READY;
    }
    descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        fprintf(stderr, "xprobe CUPTI: failed to create snapshot socket: %s\n",
                strerror(errno));
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    memcpy(address.sun_path, snapshot_socket_path,
           strlen(snapshot_socket_path) + 1U);
    if (bind(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(snapshot_socket_path, 0600) != 0 || listen(descriptor, 4) != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to initialize snapshot socket %s: %s\n",
                snapshot_socket_path, strerror(errno));
        close(descriptor);
        unlink(snapshot_socket_path);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    atomic_store_explicit(&snapshot_thread_stop, 0, memory_order_release);
    atomic_store_explicit(&snapshot_listener, descriptor, memory_order_release);
    thread_result = pthread_create(&snapshot_thread, NULL, serve_snapshots, NULL);
    if (thread_result != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to create snapshot thread: %s\n",
                strerror(thread_result));
        atomic_store_explicit(&snapshot_listener, -1, memory_order_release);
        close(descriptor);
        unlink(snapshot_socket_path);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    snapshot_thread_started = 1;
    return XPROBE_CUPTI_AGENT_READY;
}

static void stop_snapshot_server(void)
{
    int descriptor;

    if (snapshot_thread_started == 0) {
        return;
    }
    atomic_store_explicit(&snapshot_thread_stop, 1, memory_order_release);
    descriptor = atomic_exchange_explicit(&snapshot_listener, -1,
                                          memory_order_acq_rel);
    if (descriptor >= 0) {
        (void)shutdown(descriptor, SHUT_RDWR);
        if (close(descriptor) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to close snapshot socket: %s\n",
                    strerror(errno));
        }
    }
    if (pthread_join(snapshot_thread, NULL) != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to join snapshot thread\n");
    }
    snapshot_thread_started = 0;
    if (unlink(snapshot_socket_path) != 0 && errno != ENOENT) {
        fprintf(stderr, "xprobe CUPTI: failed to remove snapshot socket: %s\n",
                strerror(errno));
    }
}

static int disable_activities(void)
{
    CUptiResult result;
    int status = XPROBE_CUPTI_AGENT_READY;
    static const struct {
        uint32_t bit;
        CUpti_ActivityKind kind;
    } activities[] = {
        {XPROBE_CUPTI_ACTIVITY_MEMSET, CUPTI_ACTIVITY_KIND_MEMSET},
        {XPROBE_CUPTI_ACTIVITY_MEMCPY, CUPTI_ACTIVITY_KIND_MEMCPY},
        {XPROBE_CUPTI_ACTIVITY_KERNEL, CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL},
    };

    for (size_t index = 0U; index < sizeof(activities) / sizeof(activities[0]);
         ++index) {
        if ((enabled_activity_mask & activities[index].bit) == 0U) {
            continue;
        }
        result = cuptiActivityDisable(activities[index].kind);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiActivityDisable", result);
            status = XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        } else {
            enabled_activity_mask &= ~activities[index].bit;
        }
    }
    return status;
}

static int shutdown_agent(void)
{
    CUptiResult result;
    int status = disable_activities();

    if (subscriber_active != 0) {
        result = cuptiUnsubscribe(subscriber);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiUnsubscribe", result);
            status = XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        subscriber_active = 0;
    }
    return status;
}

static int capture_needs_record_kind(uint32_t first_kind, uint32_t second_kind)
{
    if (atomic_load_explicit(&capture_filter_enabled, memory_order_relaxed) == 0) {
        return 1;
    }
    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        uint32_t kind = capture_filters[index].record_kind;

        if (kind == first_kind || kind == second_kind) {
            return 1;
        }
    }
    return 0;
}

static int capture_needs_api_domain(uint32_t domain)
{
    if (capture_needs_record_kind(XPROBE_CUPTI_CUDA_API_ENTRY,
                                  XPROBE_CUPTI_CUDA_API_EXIT) == 0) {
        return 0;
    }
    if (atomic_load_explicit(&capture_filter_enabled, memory_order_relaxed) == 0) {
        return 1;
    }
    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        const struct xprobe_cupti_filter *filter = &capture_filters[index];

        if ((filter->record_kind == XPROBE_CUPTI_CUDA_API_ENTRY ||
             filter->record_kind == XPROBE_CUPTI_CUDA_API_EXIT) &&
            (filter->api_domain == 0U || filter->api_domain == domain)) {
            return 1;
        }
    }
    return 0;
}

static int enable_activity(uint32_t bit, CUpti_ActivityKind kind)
{
    CUptiResult result = cuptiActivityEnable(kind);

    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityEnable", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    enabled_activity_mask |= bit;
    return XPROBE_CUPTI_AGENT_READY;
}

static int api_filter_matches_callback(CUpti_CallbackDomain domain,
                                       const char *callback_name)
{
    char semantic_name[XPROBE_CUPTI_NAME_LENGTH];
    size_t length;

    copy_name(semantic_name, callback_name);
    length = bounded_name_length(semantic_name);
    if (length < XPROBE_CUPTI_NAME_LENGTH) {
        for (size_t index = length; index > 2U; --index) {
            size_t suffix = index - 2U;

            if (semantic_name[suffix] != '_' ||
                semantic_name[suffix + 1U] != 'v') {
                continue;
            }
            size_t digit = suffix + 2U;
            while (digit < length && semantic_name[digit] >= '0' &&
                   semantic_name[digit] <= '9') {
                ++digit;
            }
            if (digit == length && digit > suffix + 2U) {
                semantic_name[suffix] = '\0';
            }
            break;
        }
    }
    for (size_t index = 0U; index < XPROBE_CUPTI_FILTER_COUNT; ++index) {
        const struct xprobe_cupti_filter *filter = &capture_filters[index];

        if ((filter->record_kind == XPROBE_CUPTI_CUDA_API_ENTRY ||
             filter->record_kind == XPROBE_CUPTI_CUDA_API_EXIT) &&
            (filter->api_domain == 0U ||
             filter->api_domain == (uint32_t)domain) &&
            name_matches(filter, semantic_name) != 0) {
            return 1;
        }
    }
    return 0;
}

static int enable_filtered_callbacks(CUpti_CallbackDomain domain,
                                     uint32_t callback_count)
{
    uint32_t enabled = 0U;

    for (uint32_t callback_id = 1U; callback_id < callback_count; ++callback_id) {
        const char *callback_name = NULL;
        CUptiResult result =
            cuptiGetCallbackName(domain, callback_id, &callback_name);

        if (result == CUPTI_ERROR_INVALID_PARAMETER) {
            continue;
        }
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiGetCallbackName", result);
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        if (api_filter_matches_callback(domain, callback_name) == 0) {
            continue;
        }
        result = cuptiEnableCallback(1U, subscriber, domain, callback_id);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiEnableCallback", result);
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        ++enabled;
    }
    if (enabled == 0U) {
        fprintf(stderr,
                "xprobe CUPTI: no callback ID matched the requested API filter\n");
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    return XPROBE_CUPTI_AGENT_READY;
}

static int enable_api_callbacks(CUpti_CallbackDomain domain,
                                uint32_t callback_count)
{
    CUptiResult result;

    if (atomic_load_explicit(&capture_filter_enabled, memory_order_relaxed) == 0) {
        result = cuptiEnableDomain(1U, subscriber, domain);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiEnableDomain", result);
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        return XPROBE_CUPTI_AGENT_READY;
    }
    return enable_filtered_callbacks(domain, callback_count);
}

static int activate_capture(void)
{
#if CUPTI_API_VERSION >= 130000
    CUpti_TimestampCallbackFunc timestamp_callback = activity_timestamp;
#endif
    CUptiResult result;
    int needs_kernel =
        capture_needs_record_kind(XPROBE_CUPTI_GPU_KERNEL_START,
                                  XPROBE_CUPTI_GPU_KERNEL_END);
    int needs_memcpy =
        capture_needs_record_kind(XPROBE_CUPTI_GPU_MEMCPY_START,
                                  XPROBE_CUPTI_GPU_MEMCPY_END);
    int needs_memset =
        capture_needs_record_kind(XPROBE_CUPTI_GPU_MEMSET_START,
                                  XPROBE_CUPTI_GPU_MEMSET_END);
    int needs_activities = needs_kernel != 0 || needs_memcpy != 0 ||
                           needs_memset != 0;
    int needs_runtime = capture_needs_api_domain(CUPTI_CB_DOMAIN_RUNTIME_API);
    int needs_driver = capture_needs_api_domain(CUPTI_CB_DOMAIN_DRIVER_API);

    result = cuptiGetVersion(&runtime_cupti_version);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiGetVersion", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (monotonic_timestamp_ns(&capture_start_timestamp_ns) !=
        XPROBE_CUPTI_AGENT_READY) {
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    if (needs_runtime != 0 || needs_driver != 0) {
        result = cuptiSubscribe(&subscriber, api_callback, NULL);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiSubscribe", result);
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        subscriber_active = 1;
    }
    if (needs_activities != 0) {
#if CUPTI_API_VERSION < 130000
        int calibration_status = calibrate_activity_timestamp();
        if (calibration_status != XPROBE_CUPTI_AGENT_READY) {
            shutdown_agent();
            return calibration_status;
        }
#else
        result = cuptiActivityRegisterTimestampCallback(timestamp_callback);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiActivityRegisterTimestampCallback", result);
            shutdown_agent();
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
#endif
        result = cuptiActivityRegisterCallbacks(activity_buffer_requested,
                                                activity_buffer_completed);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiActivityRegisterCallbacks", result);
            shutdown_agent();
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
    }
    if (needs_kernel != 0 &&
        enable_activity(XPROBE_CUPTI_ACTIVITY_KERNEL,
                        CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) !=
            XPROBE_CUPTI_AGENT_READY) {
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (needs_memcpy != 0 &&
        enable_activity(XPROBE_CUPTI_ACTIVITY_MEMCPY,
                        CUPTI_ACTIVITY_KIND_MEMCPY) !=
            XPROBE_CUPTI_AGENT_READY) {
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (needs_memset != 0 &&
        enable_activity(XPROBE_CUPTI_ACTIVITY_MEMSET,
                        CUPTI_ACTIVITY_KIND_MEMSET) !=
            XPROBE_CUPTI_AGENT_READY) {
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (needs_runtime != 0) {
        if (enable_api_callbacks(CUPTI_CB_DOMAIN_RUNTIME_API,
                                 CUPTI_RUNTIME_TRACE_CBID_SIZE) !=
            XPROBE_CUPTI_AGENT_READY) {
            shutdown_agent();
            return xprobe_cupti_agent_status();
        }
    }
    if (needs_driver != 0) {
        if (enable_api_callbacks(CUPTI_CB_DOMAIN_DRIVER_API,
                                 CUPTI_DRIVER_TRACE_CBID_SIZE) !=
            XPROBE_CUPTI_AGENT_READY) {
            shutdown_agent();
            return xprobe_cupti_agent_status();
        }
    }
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_READY,
                          memory_order_relaxed);
    atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_ACTIVE,
                          memory_order_release);
    return XPROBE_CUPTI_AGENT_READY;
}

static void finalize_agent(void)
{
    if (output_path[0] != '\0' &&
        atomic_load_explicit(&output_written, memory_order_relaxed) == 0 &&
        atomic_load_explicit(&agent_status, memory_order_relaxed) ==
            XPROBE_CUPTI_AGENT_READY) {
        (void)xprobe_cupti_agent_flush();
    } else {
        stop_snapshot_server();
        shutdown_agent();
    }
}

int xprobe_cupti_agent_start(const char *configured_socket, uint64_t capacity)
{
    size_t length;

    stop_snapshot_server();
    if (shutdown_agent() != XPROBE_CUPTI_AGENT_READY) {
        return xprobe_cupti_agent_status();
    }
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_UNAVAILABLE,
                          memory_order_release);
    snapshot_socket_path[0] = '\0';
    if (allocate_capture(capacity) != XPROBE_CUPTI_AGENT_READY) {
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    if (configured_socket != NULL) {
        length = strlen(configured_socket);
        if (length >= sizeof(snapshot_socket_path)) {
            fprintf(stderr, "xprobe CUPTI: snapshot socket path is too long\n");
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        memcpy(snapshot_socket_path, configured_socket, length + 1U);
    }
    if (agent_initialized == 0) {
        agent_initialized = 1;
        if (atexit(finalize_agent) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to register exit handler\n");
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
    }
    reset_capture();
    if (configured_socket != NULL) {
        atomic_store_explicit(&capture_filter_enabled, 1, memory_order_release);
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_READY,
                              memory_order_release);
        if (start_snapshot_server() != XPROBE_CUPTI_AGENT_READY) {
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
    } else {
        atomic_store_explicit(&capture_filter_enabled, 0, memory_order_release);
        if (activate_capture() != XPROBE_CUPTI_AGENT_READY) {
            return xprobe_cupti_agent_status();
        }
    }
    return XPROBE_CUPTI_AGENT_READY;
}

int xprobe_cupti_agent_initialize(void)
{
    const char *configured_path = getenv("XPROBE_CUPTI_OUTPUT");
    const char *configured_socket = getenv("XPROBE_CUPTI_SOCKET");
    const char *configured_capacity = getenv("XPROBE_CUPTI_MAX_RECORDS");
    uint64_t capacity = XPROBE_CUPTI_DEFAULT_RECORD_CAPACITY;
    size_t length;

    output_path[0] = '\0';
    if (configured_path != NULL) {
        length = strlen(configured_path);
        if (length >= sizeof(output_path)) {
            fprintf(stderr, "xprobe CUPTI: XPROBE_CUPTI_OUTPUT is too long\n");
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        memcpy(output_path, configured_path, length + 1U);
    }
    if (configured_capacity != NULL) {
        char *end = NULL;
        unsigned long long parsed;

        errno = 0;
        parsed = strtoull(configured_capacity, &end, 10);
        if (errno != 0 || end == configured_capacity || *end != '\0' || parsed == 0U) {
            fprintf(stderr, "xprobe CUPTI: invalid XPROBE_CUPTI_MAX_RECORDS\n");
            remember_output_error();
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        capacity = (uint64_t)parsed;
    }
    return xprobe_cupti_agent_start(configured_socket, capacity);
}

int InitializeInjection(void)
{
    return xprobe_cupti_agent_initialize() == XPROBE_CUPTI_AGENT_READY;
}

int xprobe_cupti_agent_status(void)
{
    return atomic_load_explicit(&agent_status, memory_order_relaxed);
}

unsigned int xprobe_cupti_agent_last_cupti_result(void)
{
    return atomic_load_explicit(&last_cupti_result, memory_order_relaxed);
}

int xprobe_cupti_agent_flush(void)
{
    int status;

    if (xprobe_cupti_agent_status() != XPROBE_CUPTI_AGENT_READY) {
        const char *message = NULL;
        unsigned int code = xprobe_cupti_agent_last_cupti_result();
        if (cuptiGetResultString((CUptiResult)code, &message) == CUPTI_SUCCESS &&
            message != NULL) {
            fprintf(stderr, "xprobe CUPTI: agent failed after %llu records: %s\n",
                    (unsigned long long)atomic_load_explicit(&record_count,
                                                            memory_order_relaxed),
                    message);
        }
        return xprobe_cupti_agent_status();
    }
    if (output_path[0] == '\0') {
        fprintf(stderr, "xprobe CUPTI: XPROBE_CUPTI_OUTPUT is not set\n");
        remember_output_error();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    stop_snapshot_server();
    if (pthread_mutex_lock(&flush_mutex) != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to lock final flush mutex\n");
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    status = flush_activity_buffers(0);
    if (xprobe_cupti_agent_status() != XPROBE_CUPTI_AGENT_READY) {
        const char *message = NULL;
        unsigned int code = xprobe_cupti_agent_last_cupti_result();
        if (cuptiGetResultString((CUptiResult)code, &message) == CUPTI_SUCCESS &&
            message != NULL) {
            fprintf(stderr,
                    "xprobe CUPTI: activity completion failed after %llu records: %s\n",
                    (unsigned long long)atomic_load_explicit(&record_count,
                                                            memory_order_relaxed),
                    message);
        }
        status = xprobe_cupti_agent_status();
        goto unlock;
    }
    if (atomic_load_explicit(&capture_state, memory_order_relaxed) ==
        XPROBE_CUPTI_CAPTURE_ACTIVE) {
        atomic_store_explicit(&capture_state, XPROBE_CUPTI_CAPTURE_STOPPED,
                              memory_order_relaxed);
        atomic_store_explicit(&stop_reason, XPROBE_CUPTI_STOP_REQUESTED,
                              memory_order_relaxed);
    }
    status = write_output();
    if (status == XPROBE_CUPTI_AGENT_READY) {
        shutdown_agent();
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_UNAVAILABLE,
                              memory_order_release);
    }

unlock:
    if (pthread_mutex_unlock(&flush_mutex) != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to unlock final flush mutex\n");
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    return status;
}

#endif
