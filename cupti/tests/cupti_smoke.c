#include "xprobe/cupti_agent.h"

#include <stddef.h>

int main(void)
{
    if (xprobe_cupti_agent_abi_version() != XPROBE_CUPTI_AGENT_ABI_VERSION) {
        return 1;
    }
    if (sizeof(struct xprobe_cupti_output_header) != 80U) {
        return 2;
    }
    if (sizeof(struct xprobe_cupti_record) != 200U) {
        return 3;
    }
    if (offsetof(struct xprobe_cupti_output_header, feature_flags) != 20U) {
        return 4;
    }
    if (offsetof(struct xprobe_cupti_output_header, record_count) != 32U ||
        offsetof(struct xprobe_cupti_output_header, unknown_records) != 72U) {
        return 5;
    }
    if (offsetof(struct xprobe_cupti_record, grid_x) != 44U ||
        offsetof(struct xprobe_cupti_record, grid_z) != 52U ||
        offsetof(struct xprobe_cupti_record, block_x) != 56U ||
        offsetof(struct xprobe_cupti_record, runtime_correlation_id) != 68U ||
        offsetof(struct xprobe_cupti_record, name) != 72U) {
        return 6;
    }
    if (sizeof(struct xprobe_cupti_filter) != 144U ||
        sizeof(struct xprobe_cupti_control_request) != 312U) {
        return 7;
    }
    if (offsetof(struct xprobe_cupti_control_request, record_capacity) != 16U ||
        offsetof(struct xprobe_cupti_control_request, filters) != 24U ||
        offsetof(struct xprobe_cupti_filter, name) != 16U) {
        return 8;
    }
    return 0;
}
