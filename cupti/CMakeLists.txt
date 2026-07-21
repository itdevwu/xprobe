add_library(xprobe-cupti SHARED src/cupti_agent.c)

option(
  XPROBE_REQUIRE_CUPTI
  "Fail configuration when CUPTI development files are unavailable"
  OFF
)
set(XPROBE_CUDA_MAJOR "" CACHE STRING "CUDA major used to build the CUPTI agent")

find_path(
  XPROBE_CUPTI_INCLUDE_DIR
  NAMES cupti.h
  HINTS "$ENV{CUDA_PATH}" "$ENV{CUDA_HOME}" "/usr/local/cuda"
  PATH_SUFFIXES include targets/x86_64-linux/include
)
find_library(
  XPROBE_CUPTI_LIBRARY
  NAMES cupti
  HINTS "$ENV{CUDA_PATH}" "$ENV{CUDA_HOME}" "/usr/local/cuda"
  PATH_SUFFIXES lib64 targets/x86_64-linux/lib
)

target_include_directories(
  xprobe-cupti
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)
target_compile_features(xprobe-cupti PRIVATE c_std_11)
target_compile_options(xprobe-cupti PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(xprobe-cupti PROPERTIES OUTPUT_NAME xprobe-cupti)

install(
  DIRECTORY include/
  DESTINATION include
)

if(XPROBE_CUPTI_INCLUDE_DIR AND XPROBE_CUPTI_LIBRARY)
  if(NOT XPROBE_CUDA_MAJOR)
    file(READ_SYMLINK "${XPROBE_CUPTI_LIBRARY}" XPROBE_CUPTI_LIBRARY_LINK)
    string(
      REGEX MATCH
      "libcupti\\.so\\.([0-9]+)"
      XPROBE_CUPTI_SONAME
      "${XPROBE_CUPTI_LIBRARY_LINK}"
    )
    set(XPROBE_CUDA_MAJOR "${CMAKE_MATCH_1}")
  endif()
  if(NOT XPROBE_CUDA_MAJOR MATCHES "^(12|13)$")
    message(
      FATAL_ERROR
      "CUPTI agent requires CUDA major 12 or 13; set XPROBE_CUDA_MAJOR explicitly"
    )
  endif()
  find_package(Threads REQUIRED)
  target_compile_definitions(xprobe-cupti PRIVATE XPROBE_HAS_CUPTI=1 _GNU_SOURCE)
  target_include_directories(xprobe-cupti SYSTEM PRIVATE "${XPROBE_CUPTI_INCLUDE_DIR}")
  target_link_libraries(xprobe-cupti PRIVATE "${XPROBE_CUPTI_LIBRARY}" Threads::Threads)
  set_target_properties(
    xprobe-cupti
    PROPERTIES SKIP_BUILD_RPATH TRUE
  )
  set(XPROBE_CUPTI_INSTALL_DIR "lib/xprobe/cuda${XPROBE_CUDA_MAJOR}")
  message(
    STATUS
    "Building xprobe CUDA ${XPROBE_CUDA_MAJOR} Agent with ${XPROBE_CUPTI_LIBRARY}"
  )
else()
  if(XPROBE_REQUIRE_CUPTI)
    message(FATAL_ERROR "CUPTI development files are required but were not found")
  endif()
  set(XPROBE_CUPTI_INSTALL_DIR "lib/xprobe")
  message(STATUS "CUPTI development files not found; building ABI-only agent")
endif()

install(
  TARGETS xprobe-cupti
  LIBRARY DESTINATION "${XPROBE_CUPTI_INSTALL_DIR}"
)

if(BUILD_TESTING)
  add_executable(xprobe-cupti-smoke tests/cupti_smoke.c)
  target_link_libraries(xprobe-cupti-smoke PRIVATE xprobe-cupti)
  add_test(NAME cupti-smoke COMMAND xprobe-cupti-smoke)
endif()
