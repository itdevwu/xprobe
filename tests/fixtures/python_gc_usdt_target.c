#include <unistd.h>

#define XPROBE_USDT_NOTE(provider, name)                                      \
    __asm__ volatile(                                                         \
        "990: nop\n"                                                         \
        ".pushsection .note.stapsdt,\"?\",@note\n"                       \
        ".balign 4\n"                                                        \
        ".4byte 992f-991f, 994f-993f, 3\n"                                  \
        "991: .asciz \"stapsdt\"\n"                                          \
        "992: .balign 4\n"                                                   \
        "993: .8byte 990b\n"                                                 \
        ".8byte 0\n"                                                        \
        ".8byte 0\n"                                                        \
        ".asciz \"" provider "\"\n"                                         \
        ".asciz \"" name "\"\n"                                             \
        ".asciz \"\"\n"                                                    \
        "994: .balign 4\n"                                                   \
        ".popsection\n")

static __attribute__((noinline)) void python_gc_start(void)
{
    XPROBE_USDT_NOTE("python", "gc__start");
}

static __attribute__((noinline)) void python_gc_done(void)
{
    XPROBE_USDT_NOTE("python", "gc__done");
}

int main(void)
{
    for (;;) {
        python_gc_start();
        usleep(1000);
        python_gc_done();
        usleep(10000);
    }
}
