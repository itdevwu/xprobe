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
#include <cupti_runtime_cbid.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define XPROBE_CUPTI_MAX_RECORDS 65536U
#define XPROBE_CUPTI_ACTIVITY_BUFFER_SIZE (8U * 1024U * 1024U)

_Static_assert(sizeof(struct xprobe_cupti_output_header) == 48U,
               "unexpected CUPTI output header layout");
_Static_assert(sizeof(struct xprobe_cupti_record) == 200U,
               "unexpected CUPTI record layout");

static struct xprobe_cupti_record records[XPROBE_CUPTI_MAX_RECORDS];
static _Atomic uint64_t record_count;
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
static const CUpti_ActivityKind enabled_activity_kinds[] = {
    CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL,
};

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

    if (index >= XPROBE_CUPTI_MAX_RECORDS) {
        atomic_fetch_add_explicit(&dropped_records, 1U, memory_order_relaxed);
        return;
    }
    records[index] = *record;
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

static int is_launch_callback(CUpti_CallbackId callback_id)
{
    return callback_id == CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000 ||
           callback_id == CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000;
}

static void enqueue_runtime_record(const CUpti_CallbackData *data,
                                   CUpti_CallbackId callback_id, uint32_t kind,
                                   uint64_t timestamp_ns)
{
    struct xprobe_cupti_record record;

    initialize_record(&record, kind, timestamp_ns);
    record.context_id = data->contextUid;
    record.correlation_id = data->correlationId;
    record.runtime_correlation_id = data->correlationId;
    record.callback_domain = (uint32_t)CUPTI_CB_DOMAIN_RUNTIME_API;
    record.callback_id = callback_id;
    copy_name(record.name, data->functionName);
    enqueue_record(&record);
}

static void CUPTIAPI api_callback(void *userdata, CUpti_CallbackDomain domain,
                                  CUpti_CallbackId callback_id,
                                  const void *callback_data)
{
    const CUpti_CallbackData *data = callback_data;
    struct timespec timestamp;
    uint64_t timestamp_ns;

    (void)userdata;
    if (domain != CUPTI_CB_DOMAIN_RUNTIME_API || !is_launch_callback(callback_id)) {
        return;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return;
    }
    timestamp_ns = (uint64_t)timestamp.tv_sec * 1000000000U +
                   (uint64_t)timestamp.tv_nsec;
    if (data->callbackSite == CUPTI_API_ENTER) {
        enqueue_runtime_record(data, callback_id, XPROBE_CUPTI_CUDA_API_ENTRY,
                               timestamp_ns);
    } else {
        enqueue_runtime_record(data, callback_id, XPROBE_CUPTI_CUDA_API_EXIT,
                               timestamp_ns);
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
        } else {
            atomic_fetch_add_explicit(&unknown_records, 1U, memory_order_relaxed);
        }
    }

    free(buffer);
    atomic_fetch_add_explicit(&completed_buffers, 1U, memory_order_release);
}

static int wait_for_activity_buffers(uint64_t completed_before_flush)
{
    struct timespec now;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    uint64_t deadline_ns;
    uint64_t quiet_since_ns = 0U;
    uint64_t previous_requested = 0U;
    uint64_t previous_completed = 0U;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fprintf(stderr, "xprobe CUPTI: clock_gettime failed: %s\n", strerror(errno));
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    deadline_ns = (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec +
                  5000000000U;

    for (;;) {
        uint64_t requested =
            atomic_load_explicit(&requested_buffers, memory_order_relaxed);
        uint64_t completed =
            atomic_load_explicit(&completed_buffers, memory_order_acquire);
        uint64_t now_ns;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            fprintf(stderr, "xprobe CUPTI: clock_gettime failed: %s\n",
                    strerror(errno));
            return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
        }
        now_ns = (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec;
        if (completed > completed_before_flush && completed == requested) {
            if (requested != previous_requested || completed != previous_completed) {
                quiet_since_ns = now_ns;
            } else if (now_ns - quiet_since_ns >= 100000000U) {
                return XPROBE_CUPTI_AGENT_READY;
            }
        } else {
            quiet_since_ns = 0U;
        }
        previous_requested = requested;
        previous_completed = completed;

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

static int write_output(void)
{
    struct xprobe_cupti_output_header header = {0};
    uint64_t total = atomic_load_explicit(&record_count, memory_order_relaxed);
    uint64_t available = total < XPROBE_CUPTI_MAX_RECORDS ? total : XPROBE_CUPTI_MAX_RECORDS;
    int descriptor;
    int result;

    memcpy(header.magic, XPROBE_CUPTI_OUTPUT_MAGIC, sizeof(header.magic));
    header.abi_version = XPROBE_CUPTI_AGENT_ABI_VERSION;
    header.header_size = sizeof(header);
    header.record_size = sizeof(records[0]);
    header.record_count = available;
    header.dropped_records =
        atomic_load_explicit(&dropped_records, memory_order_relaxed);
    header.unknown_records =
        atomic_load_explicit(&unknown_records, memory_order_relaxed);

    descriptor = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        fprintf(stderr, "xprobe CUPTI: failed to open %s: %s\n", output_path,
                strerror(errno));
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    result = write_all(descriptor, &header, sizeof(header));
    if (result == 0) {
        result = write_all(descriptor, records, available * sizeof(records[0]));
    }
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
    CUptiResult result;
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
    result = cuptiEnableCallback(1U, subscriber, CUPTI_CB_DOMAIN_STATE,
                                 CUPTI_CBID_STATE_FATAL_ERROR);
    if (result == CUPTI_SUCCESS) {
        result = cuptiEnableCallback(1U, subscriber, CUPTI_CB_DOMAIN_RUNTIME_API,
                                     CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000);
    }
    if (result == CUPTI_SUCCESS) {
        result = cuptiEnableCallback(
            1U, subscriber, CUPTI_CB_DOMAIN_RUNTIME_API,
            CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000);
    }
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiEnableCallback", result);
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
    }
}

int xprobe_cupti_agent_initialize(void)
{
    const char *configured_path = getenv("XPROBE_CUPTI_OUTPUT");
    size_t length;

    if (agent_initialized != 0) {
        return xprobe_cupti_agent_status();
    }
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
    agent_initialized = 1;
    if (atexit(finalize_agent) != 0) {
        fprintf(stderr, "xprobe CUPTI: failed to register exit handler\n");
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_OUTPUT_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_OUTPUT_ERROR;
    }
    return initialize_agent();
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
    uint64_t completed_before_flush;

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
    completed_before_flush =
        atomic_load_explicit(&completed_buffers, memory_order_acquire);
    result = cuptiActivityFlushAll(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityFlushAll", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    if (wait_for_activity_buffers(completed_before_flush) !=
        XPROBE_CUPTI_AGENT_READY) {
        atomic_store_explicit(&agent_status, XPROBE_CUPTI_AGENT_CUPTI_ERROR,
                              memory_order_relaxed);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
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
        return xprobe_cupti_agent_status();
    }
    result = cuptiActivityGetNumDroppedRecords_v2(subscriber, NULL, 0U, &dropped);
    if (result != CUPTI_SUCCESS) {
        report_cupti_error("cuptiActivityGetNumDroppedRecords_v2", result);
        return XPROBE_CUPTI_AGENT_CUPTI_ERROR;
    }
    atomic_fetch_add_explicit(&dropped_records, dropped, memory_order_relaxed);
    return write_output();
}

#endif
