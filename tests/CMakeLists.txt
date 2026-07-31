add_executable(xprobe-uprobe-target fixtures/uprobe_target.c)
target_compile_options(xprobe-uprobe-target PRIVATE -O0 -Wall -Wextra -Werror)

add_executable(xprobe-syscall-target fixtures/syscall_target.c)
target_compile_options(xprobe-syscall-target PRIVATE -O0 -Wall -Wextra -Werror)

add_executable(xprobe-python-gc-usdt-target fixtures/python_gc_usdt_target.c)
target_compile_options(xprobe-python-gc-usdt-target PRIVATE -O0 -Wall -Wextra -Werror -no-pie)
target_link_options(xprobe-python-gc-usdt-target PRIVATE -no-pie)
