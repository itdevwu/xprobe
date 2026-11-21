// Launch an exact number of empty kernels as fast as possible, on several
// streams, so live tests can check that every activity record is retained or
// reported as dropped.
#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>
#include <unistd.h>

__global__ void xprobe_burst_kernel() {}

static void check(cudaError_t error, const char *what)
{
    if (error != cudaSuccess) {
        std::fprintf(stderr, "%s failed: %s\n", what, cudaGetErrorString(error));
        std::exit(1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        std::fprintf(stderr, "usage: %s <ready> <go> <done> <stop> <kernels-per-stream>\n", argv[0]);
        return 2;
    }
    const int per_stream = std::atoi(argv[5]);
    const int stream_count = 4;
    cudaStream_t streams[stream_count];
    for (int index = 0; index < stream_count; ++index) {
        check(cudaStreamCreate(&streams[index]), "cudaStreamCreate");
    }
    xprobe_burst_kernel<<<1, 1>>>();
    check(cudaDeviceSynchronize(), "warmup");
    FILE *ready = std::fopen(argv[1], "w");
    if (ready == nullptr) {
        return 1;
    }
    std::fclose(ready);
    while (access(argv[2], F_OK) != 0) {
        usleep(10000);
    }
    for (int launch = 0; launch < per_stream; ++launch) {
        for (int index = 0; index < stream_count; ++index) {
            xprobe_burst_kernel<<<1, 1, 0, streams[index]>>>();
        }
    }
    check(cudaDeviceSynchronize(), "burst");
    FILE *done = std::fopen(argv[3], "w");
    if (done == nullptr) {
        return 1;
    }
    std::fclose(done);
    while (access(argv[4], F_OK) != 0) {
        usleep(10000);
    }
    return 0;
}
