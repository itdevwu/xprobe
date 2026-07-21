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

int xprobe_cupti_agent_start(const char *socket_path)
{
    (void)socket_path;
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

#define XPROBE_CUPTI_MAX_RECORDS 65536U
#define XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE (8U * 1024U * 1024U)

_Static_assert(sizeof(struct xprobe_cupti_output_header) == 48U,
               "unexpected CUPTI output header layout");
_Static_assert(sizeof(struct xprobe_cupti_record) == 200U,
               "unexpected CUPTI record layout");
_Static_assert(sizeof(struct xprobe_cupti_control_request) == 16U,
               "unexpected CUPTI control request layout");

static struct xprobe_cupti_record records[XPROBE_CUPTI_MAX_RECORDS];
static _Atomic unsigned char record_ready[XPROBE_CUPTI_MAX_RECORDS];
static _Atomic uint64_t record_count;
static _Atomic uint64_t committed_record_count;
static _Atomic uint64_t dropped_records;
static _Atomic uint64_t unknown_records;
static _Atomic uint64_t requested_buffers;
static _Atomic uint64_t completed_buffers;
static _Atomic int agent_status = XPROBE_CUPTI_AGENT_UNAVAILABLE;
static _Atomic unsigned int last_cupti_result;
static _Atomic int output_written;
static CUpti_SubscriberHandle subscriber;
static int subscriber_active;
static int agent_initialized;
static size_t enabled_activity_count;
static char output_path[PATH_MAX];
static char snapshot_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t snapshot_thread;
static _Atomic int snapshot_thread_stop;
static _Atomic int snapshot_listener = -1;
static int snapshot_thread_started;
static const CUpti_ActivityKind enabled_activity_kinds[] = {
    CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL,
    CUPTI_ACTIVITY_KIND_MEMCPY,
    CUPTI_ACTIVITY_KIND_MEMSET,
};

static void shutdown_agent(void);

static void reset_capture(void)
{
    size_t index;

    for (index = 0U; index < XPROBE_CUPTI_MAX_RECORDS; ++index) {
        atomic_store_explicit(&record_ready[index], 0U, memory_order_relaxed);
    }
    atomic_store_explicit(&record_count, 0U, memory_order_relaxed);
    atomic_store_explicit(&committed_record_count, 0U, memory_order_relaxed);
    atomic_store_explicit(&dropped_records, 0U, memory_order_relaxed);
    atomic_store_explicit(&unknown_records, 0U, memory_order_relaxed);
    atomic_store_explicit(&requested_buffers, 0U, memory_order_relaxed);
    atomic_store_explicit(&completed_buffers, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_cupti_result, 0U, memory_order_relaxed);
    atomic_store_explicit(&output_written, 0, memory_order_relaxed);
}

static void remember_cupti_error(CUptiResult result)
{
    atomic_store_explicit(&last_cupti_result, (unsigned int)result,
                          memory_order_relaxed);
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_CUPTI_ERROR,
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
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    *timestamp_ns = (uint64_t)timestamp.tv_sec * 1000000000U +
                    (uint64_t)timestamp.tv_nsec;
    return XPROBE_CUPTI_AGENT_READY;
}

static uint64_t activity_timestamp(void)
{
    uint64_t timestamp_ns = 0U;

    (void)monotonic_timestamp_ns(&timestamp_ns);
    return timestamp_ns;
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

static void enqueue_record(const struct xprobe_cupti_record *record)
{
    uint64_t index = atomic_fetch_add_explicit(&record_count, 1U, memory_order_relaxed);
    uint64_t committed;

    if (index >= XPROBE_CUPTI_MAX_RECORDS) {
        atomic_fetch_add_explicit(&dropped_records, 1U, memory_order_relaxed);
        return;
    }
    records[index] = *record;
    atomic_store_explicit(&record_ready[index], 1U, memory_order_release);

    committed = atomic_load_explicit(&committed_record_count, memory_order_acquire);
    while (committed < XPROBE_CUPTI_MAX_RECORDS &&
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
    uint64_t timestamp_ns;

    (void)userdata;
    if (domain != CUPTI_CB_DOMAIN_RUNTIME_API &&
        domain != CUPTI_CB_DOMAIN_DRIVER_API) {
        return;
    }

    if (monotonic_timestamp_ns(&timestamp_ns) != XPROBE_CUPTI_AGENT_READY) {
        return;
    }
    if (data->callbackSite == CUPTI_API_ENTER) {
        enqueue_api_record(data, domain, callback_id,
                           XPROBE_CUPTI_CUDA_API_ENTRY, timestamp_ns);
    } else {
        enqueue_api_record(data, domain, callback_id,
                           XPROBE_CUPTI_CUDA_API_EXIT, timestamp_ns);
    }
}

static void CUPTIAPI activity_buffer_requested(uint8_t **buffer, size_t *size,
                                               size_t *maximum_records,
                                               CUpti_BufferCallbackRequestInfo *request_info)
{
    void *memory = NULL;
    int result = posix_memalign(&memory, 8U, XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE);

    (void)request_info;
    if (result != 0) {
        *buffer = NULL;
        *size = 0U;
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return;
    }
    *buffer = memory;
    *size = XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE;
    *maximum_records = 0U;
    atomic_fetch_add_explicit(&requested_buffers, 1U, memory_order_relaxed);
}

static void enqueue_kernel_record(const CUpti_ActivityKernel12 *kernel, uint32_t kind,
                                  uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, timestamp_ns);
    record.device_id = kernel->deviceId;
    record.context_id = kernel->contextId;
    record.stream_id = kernel->streamId;
    record.correlation_id = kernel->correlationId;
    record.grid_x = (uint32_t)kernel->gridX;
    record.grid_y = (uint32_t)kernel->gridY;
    record.grid_z = (uint32_t)kernel->gridZ;
    record.block_x = (uint32_t)kernel->blockX;
    record.block_y = (uint32_t)kernel->blockY;
    record.block_z = (uint32_t)kernel->blockZ;
    copy_name(record.name, kernel->name);
    enqueue_record(&record);
}

static void set_transfer_bytes(struct xprobe_cupti_record *record, uint64_t bytes)
{
    record->grid_x = (uint32_t)bytes;
    record->grid_y = (uint32_t)(bytes >> 32U);
}

static void enqueue_memcpy_record(const CUpti_ActivityMemcpy6 *memcpy_record,
                                  uint32_t kind, uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, timestamp_ns);
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

    initialize_record(&record, kind, timestamp_ns);
    record.device_id = memset_record->deviceId;
    record.context_id = memset_record->contextId;
    record.stream_id = memset_record->streamId;
    record.correlation_id = memset_record->correlationId;
    set_transfer_bytes(&record, memset_record->bytes);
    record.block_x = memset_record->value;
    enqueue_record(&record);
}

static void CUPTIAPI activity_buffer_completed(
    uint8_t *buffer, size_t size, size_t valid_size,
    CUpti_BufferCallbackCompleteInfo *complete_info)
{
    CUpti_Activity *activity = NULL;
    CUptiResult result;

    (void)size;
    (void)complete_info;
    for (;;) {
        result = cuptiActivityGetNextRecord_v2(subscriber, buffer, valid_size, &activity);
        if (result == CUPTI_ERROR_MAX_LIMIT_REACHED) {
            break;
        }
        if (result != CUPTI_SUCCESS) {
            remember_cupti_error(result);
            break;
        }
        if (activity->kind == CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
            const CUpti_ActivityKernel12 *kernel =
                (const CUpti_ActivityKernel12 *)activity;
            enqueue_kernel_record(kernel, XPROBE_CUPTI_GPU_KERNEL_START, kernel->start);
            enqueue_kernel_record(kernel, XPROBE_CUPTI_GPU_KERNEL_END, kernel->end);
        } else if (activity->kind == CUPTI_ACTIVITY_KIND_MEMCPY) {
            const CUpti_ActivityMemcpy6 *memcpy_record =
                (const CUpti_ActivityMemcpy6 *)activity;
            enqueue_memcpy_record(memcpy_record, XPROBE_CUPTI_GPU_MEMCPY_START,
                                  memcpy_record->start);
            enqueue_memcpy_record(memcpy_record, XPROBE_CUPTI_GPU_MEMCPY_END,
                                  memcpy_record->end);
        } else if (activity->kind == CUPTI_ACTIVITY_KIND_MEMSET) {
            const CUpti_ActivityMemset4 *memset_record =
                (const CUpti_ActivityMemset4 *)activity;
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

static void initialize_output_header(struct xprobe_cupti_output_header *header,
                                     uint64_t available)
{
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, XPROBE_CUPTI_OUTPUT_MAGIC, sizeof(header->magic));
    header->abi_version = XPROBE_CUPTI_AGENT_ABI_VERSION;
    header->header_size = sizeof(*header);
    header->record_size = sizeof(records[0]);
    header->feature_flags = XPROBE_CUPTI_FEATURE_HOST_MONOTONIC_TIMESTAMPS |
                            XPROBE_CUPTI_FEATURE_TRANSFER_RECORDS;
    header->record_count = available;
    header->dropped_records =
        atomic_load_explicit(&dropped_records, memory_order_relaxed);
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
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    result = write_capture(descriptor, 0);
    if (close(descriptor) != 0 && result == 0) {
        result = -1;
    }
    if (result != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to write %s: %s\n", output_path,
                strerror(errno));
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    atomic_store_explicit(&output_written, 1, memory_order_relaxed);
    return XPROBE_CUPTI_AGENT_READY;
}

static int flush_activity_buffers(int allow_empty_flush)
{
    CUptiResult result;
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
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    return xprobe_cupti_agent_status();
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
        int stop_requested = 0;

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
            (request.command != XPROBE_CUPTI_CONTROL_SNAPSHOT &&
             request.command != XPROBE_CUPTI_CONTROL_STOP)) {
            fprintf(stderr, "xprobe CUPTI: invalid snapshot control request\n");
        } else if (pthread_mutex_lock(&flush_mutex) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to lock snapshot flush mutex\n");
        } else {
            if (flush_activity_buffers(1) == XPROBE_CUPTI_AGENT_READY &&
                write_capture(client, 1) != 0) {
                fprintf(stderr, "xprobe CUPTI: failed to send snapshot: %s\n",
                        strerror(errno));
            }
            if (pthread_mutex_unlock(&flush_mutex) != 0) {
                fprintf(stderr, "xprobe CUPTI: failed to unlock snapshot flush mutex\n");
            }
            stop_requested = request.command == XPROBE_CUPTI_CONTROL_STOP;
        }
        if (close(client) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to close snapshot client: %s\n",
                    strerror(errno));
        }
        if (stop_requested != 0) {
            shutdown_agent();
            atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_UNAVAILABLE,
                                  memory_order_release);
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

    while (enabled_activity_count > 0U) {
        CUpti_ActivityKind kind = enabled_activity_kinds[enabled_activity_count - 1U];
        result = cuptiActivityDisable_v2(subscriber, kind, NULL);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiActivityDisable_v2", result);
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        --enabled_activity_count;
    }
    return XPROBE_CUPTI_AGENT_READY;
}

static void shutdown_agent(void)
{
    CUptiResult result;

    (void)disable_activities();
    if (subscriber_active != 0) {
        result = cuptiUnsubscribe(subscriber);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiUnsubscribe", result);
        }
        subscriber_active = 0;
    }
}

static int initialize_agent(void)
{
    CUpti_SubscriberParams subscriber_params = {0};
    CUpti_TimestampCallbackFunc timestamp_callback = activity_timestamp;
    CUptiResult result;
    size_t timestamp_callback_size = sizeof(timestamp_callback);
    uint32_t cupti_version;

    result = cuptiGetVersion(&cupti_version);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiGetVersion", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    subscriber_params.structSize = sizeof(subscriber_params);
    result = cuptiSubscribe_v2(&subscriber, api_callback, NULL, &subscriber_params);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiSubscribe_v2", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    subscriber_active = 1;
    result = cuptiActivitySetAttribute_v2(
        subscriber, CUPTI_ACTIVITY_ATTR_TIMESTAMP_CALLBACK,
        &timestamp_callback_size, &timestamp_callback);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivitySetAttribute_v2(timestamp callback)", result);
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    result = cuptiActivityRegisterCallbacks_v2(
        subscriber, activity_buffer_requested, activity_buffer_completed);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityRegisterCallbacks_v2", result);
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    for (size_t index = 0U;
         index < sizeof(enabled_activity_kinds) / sizeof(enabled_activity_kinds[0]);
         ++index) {
        result = cuptiActivityEnable_v2(subscriber, enabled_activity_kinds[index], NULL);
        if (result != CUPTI_SUCCESS) {
            report_cupti_error("cuptiActivityEnable_v2", result);
            shutdown_agent();
            return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        }
        ++enabled_activity_count;
    }
    result = cuptiEnableDomain(1U, subscriber, CUPTI_CB_DOMAIN_RUNTIME_API);
    if (result == CUPTI_SUCCESS) {
        result = cuptiEnableDomain(1U, subscriber, CUPTI_CB_DOMAIN_DRIVER_API);
    }
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiEnableDomain", result);
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_READY,
                          memory_order_relaxed);
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

int xprobe_cupti_agent_start(const char *configured_socket)
{
    size_t length;

    if (xprobe_cupti_agent_status() == XPROBE_CUPTI_AGENT_READY) {
        return xprobe_cupti_agent_status();
    }
    stop_snapshot_server();
    snapshot_socket_path[0] = '\0';
    if (configured_socket != NULL) {
        length = strlen(configured_socket);
        if (length >= sizeof(snapshot_socket_path)) {
            fprintf(stderr, "xprobe CUPTI: snapshot socket path is too long\n");
            atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                                  memory_order_relaxed);
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        memcpy(snapshot_socket_path, configured_socket, length + 1U);
    }
    if (agent_initialized == 0) {
        agent_initialized = 1;
        if (atexit(finalize_agent) != 0) {
            fprintf(stderr, "xprobe CUPTI: failed to register exit handler\n");
            atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                                  memory_order_relaxed);
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
    }
    reset_capture();
    if (initialize_agent() != XPROBE_CUPTI_AGENT_READY) {
        return xprobe_cupti_agent_status();
    }
    if (start_snapshot_server() != XPROBE_CUPTI_AGENT_READY) {
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        shutdown_agent();
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    return XPROBE_CUPTI_AGENT_READY;
}

int xprobe_cupti_agent_initialize(void)
{
    const char *configured_path = getenv("XPROBE_CUPTI_OUTPUT");
    const char *configured_socket = getenv("XPROBE_CUPTI_SOCKET");
    size_t length;

    output_path[0] = '\0';
    if (configured_path != NULL) {
        length = strlen(configured_path);
        if (length >= sizeof(output_path)) {
            fprintf(stderr, "xprobe CUPTI: XPROBE_CUPTI_OUTPUT is too long\n");
            atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                                  memory_order_relaxed);
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        memcpy(output_path, configured_path, length + 1U);
    }
    return xprobe_cupti_agent_start(configured_socket);
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
    CUptiResult result;
    size_t dropped = 0U;
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
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
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
    result = cuptiActivityGetNumDroppedRecords_v2(subscriber, NULL, 0U, &dropped);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityGetNumDroppedRecords_v2", result);
        status = XPROBE_CUPTI_AGENT_CUPTI_ERROR;
        goto unlock;
    }
    atomic_fetch_add_explicit(&dropped_records, dropped, memory_order_relaxed);
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
