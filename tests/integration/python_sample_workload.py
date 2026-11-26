#!/usr/bin/env python3
"""A hot loop on the main thread and a sleeping thread, for Python sampling tests."""
import ctypes, sys, threading, time
# Allow a non-ancestor sampler under kernel.yama.ptrace_scope=1 (test only).
ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0)

def hot_inner(n):
    total = 0
    for i in range(n):
        total += i * i
    return total

def hot_outer():
    while True:
        hot_inner(20000)

def sleeper():
    while True:
        time.sleep(0.01)

threading.Thread(target=sleeper, name="sleeper", daemon=True).start()
print("ready", flush=True)
hot_outer()
