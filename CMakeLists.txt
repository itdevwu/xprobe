cmake_minimum_required(VERSION 3.20)

project(xprobe VERSION 0.2.0 LANGUAGES C)

include(CTest)

option(XPROBE_BUILD_BPF "Build the eBPF probes" ON)
option(XPROBE_BUILD_CUPTI "Build the CUPTI agent" ON)

if(XPROBE_BUILD_BPF)
  add_subdirectory(bpf)
endif()

if(XPROBE_BUILD_CUPTI)
  add_subdirectory(cupti)
endif()

add_subdirectory(tests)
