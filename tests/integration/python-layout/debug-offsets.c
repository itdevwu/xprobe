#define Py_BUILD_CORE 1
#include <Python.h>
#include <internal/pycore_runtime.h>
#include <stddef.h>
#include <stdio.h>
#define P(name, value) printf("\"%s\": %zu,\n", name, (size_t)(value))
int main(void) {
    printf("{\n");
    P("cookie", offsetof(_Py_DebugOffsets, cookie));
    P("version", offsetof(_Py_DebugOffsets, version));
    P("runtime_interpreters_head", offsetof(_Py_DebugOffsets, runtime_state.interpreters_head));
    P("interp_threads_head", offsetof(_Py_DebugOffsets, interpreter_state.threads_head));
    P("interp_ceval_gil", offsetof(_Py_DebugOffsets, interpreter_state.gil_runtime_state));
    P("tstate_next", offsetof(_Py_DebugOffsets, thread_state.next));
    P("tstate_native_thread_id", offsetof(_Py_DebugOffsets, thread_state.native_thread_id));
    P("tstate_current_frame", offsetof(_Py_DebugOffsets, thread_state.current_frame));
    P("frame_back", offsetof(_Py_DebugOffsets, interpreter_frame.previous));
    P("frame_code", offsetof(_Py_DebugOffsets, interpreter_frame.executable));
    P("frame_owner", offsetof(_Py_DebugOffsets, interpreter_frame.owner));
    P("code_filename", offsetof(_Py_DebugOffsets, code_object.filename));
    P("code_qualname", offsetof(_Py_DebugOffsets, code_object.qualname));
    P("code_firstlineno", offsetof(_Py_DebugOffsets, code_object.firstlineno));
    P("object_type", offsetof(_Py_DebugOffsets, pyobject.ob_type));
    P("ascii_size", offsetof(_Py_DebugOffsets, unicode_object.asciiobject_size));
    P("size", sizeof(_Py_DebugOffsets));
    printf("\"end\": 0\n}\n");
    return 0;
}
