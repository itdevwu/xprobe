#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct SharedControl {
    std::uint64_t ready;
    std::uint64_t stop;
    std::uint64_t iterations;
};

static_assert(sizeof(SharedControl) == 24U);
static_assert(offsetof(SharedControl, ready) == 0U);
static_assert(offsetof(SharedControl, stop) == 8U);
static_assert(offsetof(SharedControl, iterations) == 16U);

__global__ void xprobe_multiprocess_stable_kernel(unsigned long long *output)
{
    const unsigned long long started = clock64();
    while (clock64() - started < 50000ULL) {
    }
    atomicAdd(output, 1ULL);
}

static int report_cuda_error(const char *operation, cudaError_t result)
{
    std::fprintf(stderr, "%s failed: %s\n", operation, cudaGetErrorString(result));
    return 13;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <shared-control-file>\n", argv[0]);
        return 2;
    }

    const int control_fd = open(argv[1], O_RDWR | O_CLOEXEC);
    if (control_fd < 0) {
        std::perror("open shared control");
        return 3;
    }
    void *mapping = mmap(nullptr, sizeof(SharedControl), PROT_READ | PROT_WRITE, MAP_SHARED,
                         control_fd, 0);
    if (mapping == MAP_FAILED) {
        std::perror("mmap shared control");
        close(control_fd);
        return 4;
    }
    auto *control = static_cast<SharedControl *>(mapping);

    cudaError_t result = cudaSetDevice(0);
    if (result != cudaSuccess) {
        return report_cuda_error("cudaSetDevice", result);
    }
    unsigned long long *device_output = nullptr;
    result = cudaMalloc(&device_output, sizeof(*device_output));
    if (result != cudaSuccess) {
        return report_cuda_error("cudaMalloc", result);
    }
    result = cudaMemset(device_output, 0, sizeof(*device_output));
    if (result != cudaSuccess) {
        return report_cuda_error("cudaMemset", result);
    }

    __atomic_store_n(&control->ready, 1ULL, __ATOMIC_RELEASE);
    while (__atomic_load_n(&control->stop, __ATOMIC_ACQUIRE) == 0ULL) {
        xprobe_multiprocess_stable_kernel<<<1, 1>>>(device_output);
        result = cudaGetLastError();
        if (result == cudaSuccess) {
            result = cudaDeviceSynchronize();
        }
        if (result != cudaSuccess) {
            return report_cuda_error("kernel workload", result);
        }
        __atomic_fetch_add(&control->iterations, 1ULL, __ATOMIC_RELAXED);
    }

    result = cudaFree(device_output);
    if (result == cudaSuccess) {
        result = cudaDeviceReset();
    }
    if (result != cudaSuccess) {
        return report_cuda_error("CUDA shutdown", result);
    }
    if (munmap(mapping, sizeof(SharedControl)) != 0) {
        std::perror("munmap shared control");
        return 5;
    }
    if (close(control_fd) != 0) {
        std::perror("close shared control");
        return 6;
    }
    return 0;
}
