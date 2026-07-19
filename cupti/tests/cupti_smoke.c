#include "xprobe/cupti_agent.h"

int main(void)
{
    return xprobe_cupti_agent_abi_version() == XPROBE_CUPTI_AGENT_ABI_VERSION ? 0 : 1;
}

