#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void xprobe_resolve_executable_marker(void) {}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <shared-library>\n", argv[0]);
        return 2;
    }

    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    xprobe_resolve_executable_marker();
    puts("ready");
    fflush(stdout);
    for (;;) {
        pause();
    }
}
