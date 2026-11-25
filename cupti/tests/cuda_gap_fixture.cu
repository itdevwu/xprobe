// Steady stream of small kernels with a rare host-side bubble, for
// triggered-capture tests. argv[1] is created when CUDA is ready; the loop
// stops when argv[2] exists.
#include <cuda_runtime.h>

#include <cstdio>
#include <unistd.h>

__global__ void xprobe_trigger_kernel(int *output)
{
    if (threadIdx.x == 0) {
        atomicAdd(output, 1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <ready-file> <stop-file>\n", argv[0]);
        return 2;
    }
    int *device_output = nullptr;
    cudaError_t result = cudaMalloc(&device_output, sizeof(*device_output));
    if (result == cudaSuccess) {
        result = cudaMemset(device_output, 0, sizeof(*device_output));
    }
    if (result == cudaSuccess) {
        result = cudaDeviceSynchronize();
    }
    if (result != cudaSuccess) {
        std::fprintf(stderr, "CUDA setup failed: %s\n", cudaGetErrorString(result));
        return 13;
    }
    std::FILE *ready = std::fopen(argv[1], "w");
    if (ready == nullptr || std::fclose(ready) != 0) {
        std::perror("ready file");
        return 15;
    }
    for (unsigned iteration = 1; access(argv[2], F_OK) != 0; ++iteration) {
        for (int launch = 0; launch < 20; ++launch) {
            xprobe_trigger_kernel<<<1, 32>>>(device_output);
        }
        result = cudaDeviceSynchronize();
        if (result != cudaSuccess) {
            std::fprintf(stderr, "kernel loop failed: %s\n", cudaGetErrorString(result));
            return 13;
        }
        // About once a second the GPU idles for 30 ms; otherwise for 0.2 ms.
        usleep(iteration % 2000 == 0 ? 30000 : 200);
    }
    return cudaFree(device_output) == cudaSuccess ? 0 : 13;
}
