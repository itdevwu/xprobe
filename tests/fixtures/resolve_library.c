__attribute__((visibility("default"), noinline)) void
xprobe_cpp_native_operator(long value)
    __asm__("_ZN14xprobe_fixture15native_operatorEl");

void xprobe_cpp_native_operator(long value)
{
    __asm__ volatile("" : : "r"(value) : "memory");
}

__attribute__((visibility("default"), noinline)) void
xprobe_resolve_library_marker(void)
{
    xprobe_cpp_native_operator(1);
}
