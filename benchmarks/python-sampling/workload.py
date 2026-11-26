#!/usr/bin/env python3
"""A hot leaf under a deep Python stack; prints iterations in a fixed window.

usage: workload.py <depth> <seconds> <go-file>
"""

import ctypes
import os
import sys
import time

# Allow a non-ancestor sampler under kernel.yama.ptrace_scope=1 (benchmark only).
ctypes.CDLL(None).prctl(0x59616D61, ctypes.c_ulong(-1), 0, 0, 0)


def leaf():
    total = 0
    for value in range(200):
        total += value * value
    return total


def descend(depth, deadline):
    if depth:
        return descend(depth - 1, deadline)
    iterations = 0
    while time.perf_counter() < deadline:
        leaf()
        iterations += 1
    return iterations


depth, seconds, go = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
print("ready", flush=True)
while not os.path.exists(go):
    time.sleep(0.001)
print(descend(depth, time.perf_counter() + seconds), flush=True)
# Stay alive until a sampler that outlasts the window has finished.
time.sleep(2)
