#ifndef XPROBE_CUPTI_AGENT_H
#define XPROBE_CUPTI_AGENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XPROBE_CUPTI_AGENT_ABI_VERSION 2U
#define XPROBE_CUPTI_OUTPUT_MAGIC "XPCUPTI"
#define XPROBE_CUPTI_CONTROL_MAGIC "XPCTRL\0"
#define XPROBE_CUPTI_CONTROL_VERSION 2U
#define XPROBE_CUPTI_NAME_LENGTH 128U
#define XPROBE_CUPTI_FILTER_COUNT 2U
#define XPROBE_CUPTI_VALUE_UNKNOWN UINT32_MAX

enum xprobe_cupti_feature {
    XPROBE_CUPTI_FEATURE_HOST_MONOTONIC_TIMESTAMPS = 1U << 0,
    XPROBE_CUPTI_FEATURE_TRANSFER_RECORDS = 1U << 1
};

enum xprobe_cupti_agent_status {
    XPROBE_CUPTI_AGENT_READY = 0,
    XPROBE_CUPTI_AGENT_UNAVAILABLE = 1,
    XPROBE_CUPTI_AGENT_CUPTI_ERROR = 2,
    XPROBE_CUPTI_AGENT_OUTPUT_ERROR = 3
};

enum xprobe_cupti_capture_state {
    XPROBE_CUPTI_CAPTURE_IDLE = 0,
    XPROBE_CUPTI_CAPTURE_ACTIVE = 1,
    XPROBE_CUPTI_CAPTURE_LIMIT_REACHED = 2,
    XPROBE_CUPTI_CAPTURE_STOPPED = 3,
    XPROBE_CUPTI_CAPTURE_FAILED = 4
};

enum xprobe_cupti_stop_reason {
    XPROBE_CUPTI_STOP_NONE = 0,
    XPROBE_CUPTI_STOP_REQUESTED = 1,
    XPROBE_CUPTI_STOP_RECORD_LIMIT = 2,
    XPROBE_CUPTI_STOP_CUPTI_ERROR = 3,
    XPROBE_CUPTI_STOP_OUTPUT_ERROR = 4
};

enum xprobe_cupti_control_command {
    XPROBE_CUPTI_CONTROL_ARM = 1,
    XPROBE_CUPTI_CONTROL_SNAPSHOT = 2,
    XPROBE_CUPTI_CONTROL_STOP = 3,
    XPROBE_CUPTI_CONTROL_CLOSE = 4
};

enum xprobe_cupti_name_match {
    XPROBE_CUPTI_NAME_ANY = 0,
    XPROBE_CUPTI_NAME_EXACT = 1,
    XPROBE_CUPTI_NAME_PREFIX = 2,
    XPROBE_CUPTI_NAME_SUFFIX = 3,
    XPROBE_CUPTI_NAME_CONTAINS = 4
};

struct xprobe_cupti_filter {
    uint32_t record_kind;
    uint32_t api_domain;
    uint32_t memcpy_kind;
    uint32_t name_match;
    char name[XPROBE_CUPTI_NAME_LENGTH];
};

struct xprobe_cupti_control_request {
    char magic[8];
    uint32_t version;
    uint32_t command;
    uint64_t record_capacity;
    struct xprobe_cupti_filter filters[XPROBE_CUPTI_FILTER_COUNT];
};

enum xprobe_cupti_record_kind {
    XPROBE_CUPTI_CUDA_API_ENTRY = 1,
    XPROBE_CUPTI_CUDA_API_EXIT = 2,
    XPROBE_CUPTI_GPU_KERNEL_START = 3,
    XPROBE_CUPTI_GPU_KERNEL_END = 4,
    XPROBE_CUPTI_GPU_MEMCPY_START = 5,
    XPROBE_CUPTI_GPU_MEMCPY_END = 6,
    XPROBE_CUPTI_GPU_MEMSET_START = 7,
    XPROBE_CUPTI_GPU_MEMSET_END = 8
};

struct xprobe_cupti_output_header {
    char magic[8];
    uint32_t abi_version;
    uint32_t header_size;
    uint32_t record_size;
    uint32_t feature_flags;
    uint32_t capture_state;
    uint32_t stop_reason;
    uint64_t record_count;
    uint64_t record_capacity;
    uint64_t observed_records;
    uint64_t agent_dropped_records;
    uint64_t cupti_dropped_records;
    uint64_t unknown_records;
};

struct xprobe_cupti_record {
    uint64_t timestamp_ns;
    uint32_t kind;
    uint32_t pid;
    uint32_t tid;
    uint32_t device_id;
    uint32_t context_id;
    uint32_t stream_id;
    uint32_t correlation_id;
    uint32_t callback_domain;
    uint32_t callback_id;
    uint32_t grid_x;
    uint32_t grid_y;
    uint32_t grid_z;
    uint32_t block_x;
    uint32_t block_y;
    uint32_t block_z;
    uint32_t runtime_correlation_id;
    char name[XPROBE_CUPTI_NAME_LENGTH];
};

/*
 * For memcpy and memset records, grid_x/grid_y hold the low/high halves of the
 * byte count. grid_z holds the CUpti_ActivityMemcpyKind for memcpy records,
 * and block_x holds the assigned value for memset records.
 */

unsigned int xprobe_cupti_agent_abi_version(void);
int xprobe_cupti_agent_initialize(void);
int xprobe_cupti_agent_start(const char *socket_path, uint64_t record_capacity);
int xprobe_cupti_agent_status(void);
unsigned int xprobe_cupti_agent_last_cupti_result(void);
int xprobe_cupti_agent_flush(void);

/* CUDA calls this entry point when the library is loaded via CUDA_INJECTION64_PATH. */
int InitializeInjection(void);

#ifdef __cplusplus
}
#endif

#endif
