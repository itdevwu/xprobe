#include <cuda_runtime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

void check_cuda(cudaError_t result, const char *operation)
{
    if (result != cudaSuccess) {
        std::fprintf(stderr, "%s failed: %s\n", operation,
                     cudaGetErrorString(result));
        std::exit(1);
    }
}

__global__ void xprobe_precision_kernel(unsigned long long cycles)
{
    const unsigned long long start = clock64();
    while (clock64() - start < cycles) {
        asm volatile("");
    }
}

__global__ void xprobe_overhead_kernel()
{
    asm volatile("");
}

__global__ void xprobe_target_rate_kernel(unsigned long long cycles)
{
    const unsigned long long start = clock64();
    while (clock64() - start < cycles) {
        asm volatile("");
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::fprintf(stderr,
                     "usage: cuda_benchmark <output-json> <launches> <rounds>\n");
        return 2;
    }

    const char *output_path = argv[1];
    const int launches = std::stoi(argv[2]);
    const int rounds = std::stoi(argv[3]);
    if (launches <= 0 || rounds <= 0) {
        std::fprintf(stderr, "launches and rounds must be positive\n");
        return 2;
    }

    check_cuda(cudaSetDevice(0), "cudaSetDevice");
    cudaDeviceProp properties{};
    check_cuda(cudaGetDeviceProperties(&properties, 0),
               "cudaGetDeviceProperties");
    int clock_rate_khz = 0;
    check_cuda(cudaDeviceGetAttribute(&clock_rate_khz, cudaDevAttrClockRate, 0),
               "cudaDeviceGetAttribute(clock rate)");

    xprobe_overhead_kernel<<<1, 1>>>();
    check_cuda(cudaGetLastError(), "warm-up kernel launch");
    check_cuda(cudaDeviceSynchronize(), "warm-up synchronization");

    cudaEvent_t precision_start;
    cudaEvent_t precision_end;
    check_cuda(cudaEventCreate(&precision_start), "cudaEventCreate(start)");
    check_cuda(cudaEventCreate(&precision_end), "cudaEventCreate(end)");
    check_cuda(cudaEventRecord(precision_start), "cudaEventRecord(start)");
    constexpr unsigned long long precision_duration_ms = 5;
    const unsigned long long precision_cycles =
        static_cast<unsigned long long>(clock_rate_khz) * precision_duration_ms;
    xprobe_precision_kernel<<<1, 1>>>(precision_cycles);
    check_cuda(cudaGetLastError(), "precision kernel launch");
    check_cuda(cudaEventRecord(precision_end), "cudaEventRecord(end)");
    check_cuda(cudaEventSynchronize(precision_end), "cudaEventSynchronize");
    float precision_ms = 0.0F;
    check_cuda(cudaEventElapsedTime(&precision_ms, precision_start, precision_end),
               "cudaEventElapsedTime");
    check_cuda(cudaEventDestroy(precision_start), "cudaEventDestroy(start)");
    check_cuda(cudaEventDestroy(precision_end), "cudaEventDestroy(end)");

    std::vector<long long> round_host_ns;
    round_host_ns.reserve(static_cast<size_t>(rounds));
    for (int round = 0; round < rounds; ++round) {
        const auto start = std::chrono::steady_clock::now();
        for (int launch = 0; launch < launches; ++launch) {
            xprobe_overhead_kernel<<<1, 1>>>();
        }
        check_cuda(cudaGetLastError(), "overhead kernel launch");
        check_cuda(cudaDeviceSynchronize(), "overhead synchronization");
        const auto end = std::chrono::steady_clock::now();
        round_host_ns.push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
                .count());
    }

    constexpr int target_rate_launches = 200;
    constexpr unsigned long long target_rate_duration_ms = 1;
    const unsigned long long target_rate_cycles =
        static_cast<unsigned long long>(clock_rate_khz) * target_rate_duration_ms;
    std::vector<long long> target_rate_round_host_ns;
    target_rate_round_host_ns.reserve(static_cast<size_t>(rounds));
    for (int round = 0; round < rounds; ++round) {
        const auto start = std::chrono::steady_clock::now();
        for (int launch = 0; launch < target_rate_launches; ++launch) {
            xprobe_target_rate_kernel<<<1, 1>>>(target_rate_cycles);
        }
        check_cuda(cudaGetLastError(), "target-rate kernel launch");
        check_cuda(cudaDeviceSynchronize(), "target-rate synchronization");
        const auto end = std::chrono::steady_clock::now();
        target_rate_round_host_ns.push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
                .count());
    }

    std::ofstream output(output_path);
    if (!output) {
        std::fprintf(stderr, "failed to open benchmark output %s\n", output_path);
        return 1;
    }
    output << "{\n"
           << "  \"gpu\": \"" << properties.name << "\",\n"
           << "  \"compute_capability\": \"" << properties.major << '.'
           << properties.minor << "\",\n"
           << "  \"stress_launches_per_round\": " << launches << ",\n"
           << "  \"target_rate_launches_per_round\": " << target_rate_launches
           << ",\n"
           << "  \"rounds\": " << rounds << ",\n"
           << "  \"precision_cuda_event_ns\": "
           << static_cast<unsigned long long>(precision_ms * 1000000.0F) << ",\n"
           << "  \"stress_round_host_ns\": [";
    for (size_t index = 0; index < round_host_ns.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << round_host_ns[index];
    }
    output << "],\n  \"target_rate_round_host_ns\": [";
    for (size_t index = 0; index < target_rate_round_host_ns.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << target_rate_round_host_ns[index];
    }
    output << "]\n}\n";
    if (!output) {
        std::fprintf(stderr, "failed to write benchmark output %s\n", output_path);
        return 1;
    }

    check_cuda(cudaDeviceReset(), "cudaDeviceReset");
    return 0;
}
