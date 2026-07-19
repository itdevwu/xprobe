#include "xprobe/cupti_agent.h"

int main(void)
{
    if (xprobe_cupti_agent_abi_version() != XPROBE_CUPTI_AGENT_ABI_VERSION) {
        return 1;
    }
    if (sizeof(struct xprobe_cupti_output_header) != 48U) {
        return 2;
    }
    if (sizeof(struct xprobe_cupti_record) != 200U) {
        return 3;
    }
    return 0;
}
