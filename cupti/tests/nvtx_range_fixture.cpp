#include <nvtx3/nvToolsExt.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::string read_mode(const char *path)
{
    std::ifstream input(path);
    std::string mode;
    input >> mode;
    return mode;
}

void nested_ranges()
{
    nvtxRangePushA("xprobe_outer");
    nvtxEventAttributes_t attributes = {};
    attributes.version = NVTX_VERSION;
    attributes.size = NVTX_EVENT_ATTRIB_STRUCT_SIZE;
    attributes.messageType = NVTX_MESSAGE_TYPE_ASCII;
    attributes.message.ascii = "xprobe_inner_ex";
    nvtxRangePushEx(&attributes);
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    nvtxRangePop();
    nvtxRangePop();
}

void cross_thread_range()
{
    nvtxRangeId_t id = nvtxRangeStartA("xprobe_cross_thread");
    std::thread end_thread([id] {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        nvtxRangeEnd(id);
    });
    end_thread.join();
}

void long_range()
{
    static const std::string name =
        "xprobe_long_range_" + std::string(180, 'x');
    nvtxRangePushA(name.c_str());
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    nvtxRangePop();
}

void unsupported_registered_range()
{
    static const nvtxStringHandle_t name =
        nvtxDomainRegisterStringA(nullptr, "xprobe_registered");
    nvtxEventAttributes_t attributes = {};
    attributes.version = NVTX_VERSION;
    attributes.size = NVTX_EVENT_ATTRIB_STRUCT_SIZE;
    attributes.messageType = NVTX_MESSAGE_TYPE_REGISTERED;
    attributes.message.registered = name;
    nvtxRangePushEx(&attributes);
    nvtxRangePop();
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "usage: nvtx_range_fixture <mode-file>\n";
        return 2;
    }
    nvtxRangePushA("xprobe_init");
    nvtxRangePop();
    std::cout << "ready" << std::endl;

    for (;;) {
        const std::string mode = read_mode(argv[1]);
        unsupported_registered_range();
        if (mode == "nested") {
            nested_ranges();
        } else if (mode == "cross") {
            cross_thread_range();
        } else if (mode == "long") {
            long_range();
        } else {
            std::cerr << "unknown mode: " << mode << '\n';
            return 3;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
