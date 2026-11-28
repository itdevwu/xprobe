// Steady stream of small kernels with rare host-side bubbles, for
// triggered-capture tests. argv[1] is created when CUDA is ready; the loop
// stops when argv[2] exists.
//
// About once a second the whole GPU idles for 30 ms. Half a second later the
// main stream pauses for 30 ms again, but a kernel on a side stream keeps the
// device busy throughout: a stream gap that is not device idle time.
#include <cuda_runtime.h>

#include <cstdio>
#include <unistd.h>

__global__ void xprobe_trigger_kernel(int *output)
{
    if (threadIdx.x == 0) {
        atomicAdd(output, 1);
    }
}

__device__ unsigned long long xprobe_global_ns()
{
    unsigned long long now;
    asm volatile("mov.u64 %0, %%globaltimer;" : "=l"(now));
    return now;
}

// Keeps the device busy for `duration_ns` of GPU wall time.
__global__ void xprobe_side_kernel(unsigned long long duration_ns, int *output)
{
    const unsigned long long start = xprobe_global_ns();
    while (xprobe_global_ns() - start < duration_ns) {
    }
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
    cudaStream_t main_stream = nullptr;
    cudaStream_t side_stream = nullptr;
    cudaError_t result = cudaMalloc(&device_output, sizeof(*device_output));
    if (result == cudaSuccess) {
        result = cudaMemset(device_output, 0, sizeof(*device_output));
    }
    // Non-blocking streams do not synchronize with each other implicitly.
    if (result == cudaSuccess) {
        result = cudaStreamCreateWithFlags(&main_stream, cudaStreamNonBlocking);
    }
    if (result == cudaSuccess) {
        result = cudaStreamCreateWithFlags(&side_stream, cudaStreamNonBlocking);
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
        const bool idle = iteration % 2000 == 0;
        const bool side = iteration % 2000 == 1000;
        if (side) {
            xprobe_side_kernel<<<1, 32, 0, side_stream>>>(45000000ULL, device_output);
        }
        for (int launch = 0; launch < 20; ++launch) {
            xprobe_trigger_kernel<<<1, 32, 0, main_stream>>>(device_output);
        }
        result = cudaStreamSynchronize(main_stream);
        if (result != cudaSuccess) {
            std::fprintf(stderr, "kernel loop failed: %s\n", cudaGetErrorString(result));
            return 13;
        }
        usleep(idle || side ? 30000 : 200);
        if (side) {
            result = cudaStreamSynchronize(side_stream);
            if (result != cudaSuccess) {
                std::fprintf(stderr, "side kernel failed: %s\n", cudaGetErrorString(result));
                return 13;
            }
        }
    }
    cudaStreamDestroy(side_stream);
    cudaStreamDestroy(main_stream);
    return cudaFree(device_output) == cudaSuccess ? 0 : 13;
}
