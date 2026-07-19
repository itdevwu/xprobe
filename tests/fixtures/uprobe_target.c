#include <unistd.h>

__attribute__((noinline, visibility("default"))) void xprobe_test_marker(void)
{
    __asm__ volatile("" ::: "memory");
}

int main(void)
{
    for (;;) {
        xprobe_test_marker();
        usleep(10000);
    }
}
