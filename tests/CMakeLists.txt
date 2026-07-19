add_executable(xprobe-uprobe-target fixtures/uprobe_target.c)
target_compile_options(xprobe-uprobe-target PRIVATE -O0 -Wall -Wextra -Werror)
