#include <cuda_runtime.h>

#include <cstdio>
#include <unistd.h>

__global__ void xprobe_aggregate_primary(int *output)
{
    *output += 1;
}

__global__ void xprobe_aggregate_secondary(int *output)
{
    *output += 2;
}

static int report_cuda_error(const char *operation, cudaError_t result)
{
    std::fprintf(stderr, "%s failed: %s\n", operation, cudaGetErrorString(result));
    return 13;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <ready-file> <stop-file>\n", argv[0]);
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

    FILE *ready = std::fopen(argv[1], "w");
    if (ready == nullptr || std::fclose(ready) != 0) {
        std::perror("ready file");
        return 5;
    }
    while (access(argv[2], F_OK) != 0) {
        xprobe_aggregate_primary<<<1, 1>>>(device_output);
        xprobe_aggregate_secondary<<<1, 1>>>(device_output);
        result = cudaGetLastError();
        if (result == cudaSuccess) {
            result = cudaDeviceSynchronize();
        }
        if (result != cudaSuccess) {
            return report_cuda_error("kernel workload", result);
        }
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
