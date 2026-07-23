#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end)
{
    time_t seconds = end->tv_sec - start->tv_sec;
    long nanoseconds = end->tv_nsec - start->tv_nsec;

    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += 1000000000L;
    }
    return (uint64_t)seconds * 1000000000ULL + (uint64_t)nanoseconds;
}

static uint64_t timeval_us(const struct timeval *value)
{
    return (uint64_t)value->tv_sec * 1000000ULL + (uint64_t)value->tv_usec;
}

static uint64_t process_rss_kib(pid_t pid)
{
    char path[64];
    char line[256];
    FILE *status;
    uint64_t rss = 0U;
    unsigned long long parsed_rss;

    if (snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid) < 0) {
        return 0U;
    }
    status = fopen(path, "r");
    if (status == NULL) {
        return 0U;
    }
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "VmRSS: %llu kB", &parsed_rss) == 1) {
            rss = (uint64_t)parsed_rss;
            break;
        }
    }
    if (ferror(status) != 0 || fclose(status) != 0) {
        return 0U;
    }
    return rss;
}

int main(int argc, char **argv)
{
    struct timespec started;
    struct timespec finished;
    struct timespec interval = {.tv_sec = 0, .tv_nsec = 10000000L};
    struct rusage usage;
    pid_t target_pid;
    pid_t child;
    int status = 0;
    uint64_t target_start_rss;
    uint64_t target_peak_rss;
    FILE *output;

    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <metrics-output> <target-pid> <command> [args...]\n",
                argv[0]);
        return 2;
    }
    target_pid = (pid_t)strtol(argv[2], NULL, 10);
    target_start_rss = process_rss_kib(target_pid);
    if (target_pid <= 0 || target_start_rss == 0U) {
        fprintf(stderr, "failed to read target process RSS\n");
        return 3;
    }
    target_peak_rss = target_start_rss;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        perror("clock_gettime");
        return 4;
    }
    child = fork();
    if (child < 0) {
        perror("fork");
        return 5;
    }
    if (child == 0) {
        execvp(argv[3], &argv[3]);
        perror("execvp");
        _exit(127);
    }

    for (;;) {
        pid_t result = wait4(child, &status, WNOHANG, &usage);
        uint64_t target_rss = process_rss_kib(target_pid);

        if (target_rss > target_peak_rss) {
            target_peak_rss = target_rss;
        }
        if (result == child) {
            break;
        }
        if (result < 0) {
            perror("wait4");
            return 6;
        }
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) {
            perror("nanosleep");
            return 7;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) {
        perror("clock_gettime");
        return 8;
    }
    output = fopen(argv[1], "w");
    if (output == NULL) {
        perror("metrics output");
        return 9;
    }
    fprintf(output, "wall_ns %llu\n",
            (unsigned long long)elapsed_ns(&started, &finished));
    fprintf(output, "user_us %llu\n",
            (unsigned long long)timeval_us(&usage.ru_utime));
    fprintf(output, "system_us %llu\n",
            (unsigned long long)timeval_us(&usage.ru_stime));
    fprintf(output, "max_rss_kib %ld\n", usage.ru_maxrss);
    fprintf(output, "target_start_rss_kib %llu\n",
            (unsigned long long)target_start_rss);
    fprintf(output, "target_peak_rss_kib %llu\n",
            (unsigned long long)target_peak_rss);
    if (fclose(output) != 0) {
        perror("metrics output");
        return 10;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        raise(WTERMSIG(status));
    }
    return 11;
}
