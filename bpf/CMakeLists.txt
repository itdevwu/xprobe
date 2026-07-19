find_program(XPROBE_CLANG clang)

if(XPROBE_CLANG)
  set(XPROBE_BPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/xprobe.bpf.o")
  add_custom_command(
    OUTPUT "${XPROBE_BPF_OBJECT}"
    COMMAND
      "${XPROBE_CLANG}" -target bpf -D__TARGET_ARCH_x86
      -I/usr/include/x86_64-linux-gnu -O2 -g -Wall -Werror
      -c "${CMAKE_CURRENT_SOURCE_DIR}/xprobe.bpf.c" -o "${XPROBE_BPF_OBJECT}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/xprobe.bpf.c"
    VERBATIM
  )
  add_custom_target(xprobe-bpf ALL DEPENDS "${XPROBE_BPF_OBJECT}")
else()
  message(WARNING "Clang was not found; the xprobe-bpf target will be skipped")
  add_custom_target(
    xprobe-bpf
    COMMAND "${CMAKE_COMMAND}" -E echo "xprobe-bpf skipped: clang not found"
    VERBATIM
  )
endif()
