#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static volatile uint64_t sink;

static void stop_workload(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static uint64_t monotonic_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

__attribute__((noinline)) uint64_t xprobe_native_hot_loop(uint64_t seed)
{
    uint64_t value = seed | 1U;

    for (uint64_t index = 0; index < 500000U; ++index) {
        value ^= value << 13U;
        value ^= value >> 7U;
        value ^= value << 17U;
    }
    return value;
}

static void write_metrics(const char *path, uint64_t iterations)
{
    char replacement[4096];
    FILE *output;

    if (snprintf(replacement, sizeof(replacement), "%s.next", path) < 0 ||
        strlen(path) + sizeof(".next") > sizeof(replacement)) {
        fprintf(stderr, "metrics path is too long\n");
        exit(3);
    }
    output = fopen(replacement, "w");
    if (output == NULL) {
        perror("metrics output");
        exit(4);
    }
    if (fprintf(output,
                "{\"count\":%" PRIu64 ",\"timestamp_ns\":%" PRIu64 "}\n",
                iterations, monotonic_ns()) < 0 || fclose(output) != 0) {
        perror("metrics output");
        exit(5);
    }
    if (rename(replacement, path) != 0) {
        perror("rename metrics");
        exit(6);
    }
}

int main(int argc, char **argv)
{
    struct sigaction action = {0};
    uint64_t iterations = 0U;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <metrics-output>\n", argv[0]);
        return 1;
    }
    action.sa_handler = stop_workload;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0) {
        perror("sigaction");
        return 2;
    }
    write_metrics(argv[1], iterations);
    printf("{\"language\":\"native\",\"pid\":%ld}\n", (long)getpid());
    fflush(stdout);
    while (running != 0) {
        sink = xprobe_native_hot_loop(sink + iterations + 1U);
        ++iterations;
        if (iterations % 32U == 0U) {
            write_metrics(argv[1], iterations);
        }
    }
    write_metrics(argv[1], iterations);
    return 0;
}
