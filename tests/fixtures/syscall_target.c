#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    for (;;) {
        void *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            return 1;
        *(volatile char *)mapping = 1;
        if (munmap(mapping, 4096) != 0)
            return 1;
        usleep(10000);
    }
}
