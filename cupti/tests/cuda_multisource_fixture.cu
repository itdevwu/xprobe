#include <cuda_runtime.h>

#include <cstdio>
#include <unistd.h>

__global__ void xprobe_multisource_kernel(int *output)
{
    *output += 1;
}

extern "C" __attribute__((noinline, visibility("default"))) void
xprobe_request_marker()
{
    __asm__ volatile("" ::: "memory");
}

static int report_cuda_error(const char *operation, cudaError_t result)
{
    std::fprintf(stderr, "%s failed: %s\n", operation, cudaGetErrorString(result));
    return 13;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <ready-file> <go-file> <stop-file>\n",
                     argv[0]);
        return 2;
    }
    cudaError_t result = cudaSetDevice(0);
    if (result != cudaSuccess) {
        return report_cuda_error("cudaSetDevice", result);
    }
    int *device_output = nullptr;
    result = cudaMalloc(&device_output, sizeof(*device_output));
    if (result != cudaSuccess) {
        return report_cuda_error("cudaMalloc", result);
    }
    result = cudaMemset(device_output, 0, sizeof(*device_output));
    if (result != cudaSuccess) {
        return report_cuda_error("cudaMemset", result);
    }

    FILE *ready = std::fopen(argv[1], "w");
    if (ready == nullptr || std::fclose(ready) != 0) {
        std::perror("ready file");
        return 15;
    }
    while (access(argv[2], F_OK) != 0) {
        usleep(10000);
    }

    int launches = 0;
    while (launches < 3 || access(argv[3], F_OK) != 0) {
        xprobe_request_marker();
        xprobe_multisource_kernel<<<1, 1>>>(device_output);
        result = cudaGetLastError();
        if (result == cudaSuccess) {
            result = cudaDeviceSynchronize();
        }
        if (result != cudaSuccess) {
            return report_cuda_error("kernel launch", result);
        }
        ++launches;
        usleep(50000);
    }

    result = cudaFree(device_output);
    if (result == cudaSuccess) {
        result = cudaDeviceReset();
    }
    if (result != cudaSuccess) {
        return report_cuda_error("CUDA shutdown", result);
    }
    return 0;
}
