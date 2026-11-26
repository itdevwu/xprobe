#define Py_BUILD_CORE 1
#include <Python.h>
#include <frameobject.h>
#include <stddef.h>
#include <stdio.h>
#if PY_MINOR_VERSION >= 11
#include <internal/pycore_frame.h>
#endif
#include <internal/pycore_runtime.h>
#include <internal/pycore_interp.h>
#if PY_MINOR_VERSION >= 12
#include <internal/pycore_gil.h>
#endif
#define P(name, value) printf("\"%s\": %zu,\n", name, (size_t)(value))
int main(void) {
    printf("{\n\"version\": \"%d.%d\",\n", PY_MAJOR_VERSION, PY_MINOR_VERSION);
    P("runtime_interpreters_head", offsetof(_PyRuntimeState, interpreters.head));
#if PY_MINOR_VERSION <= 11
    P("runtime_gil_last_holder", offsetof(_PyRuntimeState, ceval.gil.last_holder));
    P("runtime_gil_locked", offsetof(_PyRuntimeState, ceval.gil.locked));
    P("runtime_gil_switch_number", offsetof(_PyRuntimeState, ceval.gil.switch_number));
#else
    P("gil_locked", offsetof(struct _gil_runtime_state, locked));
    P("interp_ceval_gil", offsetof(PyInterpreterState, ceval.gil));
    P("gil_last_holder", offsetof(struct _gil_runtime_state, last_holder));
    P("gil_switch_number", offsetof(struct _gil_runtime_state, switch_number));
#endif
#if PY_MINOR_VERSION <= 10
    P("interp_threads_head", offsetof(PyInterpreterState, tstate_head));
#else
    P("interp_threads_head", offsetof(PyInterpreterState, threads.head));
#endif
    P("tstate_next", offsetof(PyThreadState, next));
    P("tstate_thread_id", offsetof(PyThreadState, thread_id));
#if PY_MINOR_VERSION >= 11
    P("tstate_native_thread_id", offsetof(PyThreadState, native_thread_id));
#endif
#if PY_MINOR_VERSION <= 10
    P("tstate_frame", offsetof(PyThreadState, frame));
    P("frame_back", offsetof(PyFrameObject, f_back));
    P("frame_code", offsetof(PyFrameObject, f_code));
#elif PY_MINOR_VERSION <= 12
    P("tstate_cframe", offsetof(PyThreadState, cframe));
    P("cframe_current_frame", offsetof(_PyCFrame, current_frame));
    P("frame_back", offsetof(_PyInterpreterFrame, previous));
    P("frame_code", offsetof(_PyInterpreterFrame, f_code));
    P("frame_owner", offsetof(_PyInterpreterFrame, owner));
#if PY_MINOR_VERSION == 12
    P("frame_owner_size", sizeof(((_PyInterpreterFrame *)0)->owner));
    /* Owners from this value up are not Python frames. */
    P("first_non_python_owner", FRAME_OWNED_BY_CSTACK);
#endif
#else
    P("tstate_current_frame", offsetof(PyThreadState, current_frame));
    P("frame_back", offsetof(_PyInterpreterFrame, previous));
    P("frame_code", offsetof(_PyInterpreterFrame, f_executable));
    P("frame_owner", offsetof(_PyInterpreterFrame, owner));
    P("frame_owner_size", sizeof(((_PyInterpreterFrame *)0)->owner));
#if PY_MINOR_VERSION >= 14
    P("first_non_python_owner", FRAME_OWNED_BY_INTERPRETER);
#else
    P("first_non_python_owner", FRAME_OWNED_BY_CSTACK);
#endif
    P("debug_offsets", offsetof(_PyRuntimeState, debug_offsets));
#endif
#if PY_MINOR_VERSION == 11
    P("frame_owner_size", sizeof(((_PyInterpreterFrame *)0)->owner));
#endif
    P("code_filename", offsetof(PyCodeObject, co_filename));
    P("code_name", offsetof(PyCodeObject, co_name));
#if PY_MINOR_VERSION >= 11
    P("code_qualname", offsetof(PyCodeObject, co_qualname));
#endif
    P("code_firstlineno", offsetof(PyCodeObject, co_firstlineno));
    P("object_type", offsetof(PyObject, ob_type));
    P("ascii_length", offsetof(PyASCIIObject, length));
    P("ascii_state", offsetof(PyASCIIObject, state));
    P("ascii_size", sizeof(PyASCIIObject));
    P("compact_size", sizeof(PyCompactUnicodeObject));
    printf("\"end\": 0\n}\n");
    return 0;
}
