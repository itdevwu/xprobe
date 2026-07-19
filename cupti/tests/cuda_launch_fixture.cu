#include <cuda_runtime.h>

#include <cstdio>
#include <vector>

__global__ void xprobe_test_kernel(const int *left, const int *right, int *output,
                                   int length)
{
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < length) {
        output[index] = left[index] + right[index];
    }
}

int main()
{
    cudaError_t result = cudaSetDevice(0);
    if (result != cudaSuccess) {
        std::fprintf(stderr, "cudaSetDevice failed: %s\n", cudaGetErrorString(result));
        return 9;
    }
    constexpr int element_count = 1 << 20;
    constexpr size_t byte_count = element_count * sizeof(int);
    std::vector<int> host_left(element_count, 2);
    std::vector<int> host_right(element_count, 3);
    std::vector<int> host_output(element_count);
    int *device_left = nullptr;
    int *device_right = nullptr;
    int *device_output = nullptr;
    result = cudaMalloc(&device_left, byte_count);
    if (result == cudaSuccess) {
        result = cudaMalloc(&device_right, byte_count);
    }
    if (result == cudaSuccess) {
        result = cudaMalloc(&device_output, byte_count);
    }
    if (result != cudaSuccess) {
        std::fprintf(stderr, "cudaMalloc failed: %s\n", cudaGetErrorString(result));
        return 13;
    }
    result = cudaMemcpy(device_left, host_left.data(), byte_count, cudaMemcpyHostToDevice);
    if (result == cudaSuccess) {
        result =
            cudaMemcpy(device_right, host_right.data(), byte_count, cudaMemcpyHostToDevice);
    }
    if (result != cudaSuccess) {
        std::fprintf(stderr, "cudaMemcpy H2D failed: %s\n", cudaGetErrorString(result));
        return 13;
    }
    for (int launch = 0; launch < 3; ++launch) {
        xprobe_test_kernel<<<(element_count + 255) / 256, 256>>>(
            device_left, device_right, device_output, element_count);
        result = cudaGetLastError();
        if (result != cudaSuccess) {
            std::fprintf(stderr, "kernel launch failed: %s\n", cudaGetErrorString(result));
            return 13;
        }
    }
    result = cudaDeviceSynchronize();
    if (result != cudaSuccess) {
        std::fprintf(stderr, "cudaDeviceSynchronize failed: %s\n", cudaGetErrorString(result));
        return 13;
    }
    result =
        cudaMemcpy(host_output.data(), device_output, byte_count, cudaMemcpyDeviceToHost);
    if (result != cudaSuccess || host_output.front() != 5 || host_output.back() != 5) {
        std::fprintf(stderr,
                     "cudaMemcpy D2H or result validation failed: %s (first=%d, "
                     "last=%d)\n",
                     cudaGetErrorString(result), host_output.front(), host_output.back());
        return 13;
    }
    result = cudaDeviceReset();
    if (result != cudaSuccess) {
        std::fprintf(stderr, "cudaDeviceReset failed: %s\n", cudaGetErrorString(result));
        return 16;
    }
    return 0;
}
