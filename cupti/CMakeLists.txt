add_library(xprobe-cupti SHARED src/cupti_agent.c)

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
  TARGETS xprobe-cupti
  LIBRARY DESTINATION lib/xprobe
)
install(
  DIRECTORY include/
  DESTINATION include
)

if(XPROBE_CUPTI_INCLUDE_DIR AND XPROBE_CUPTI_LIBRARY)
  find_package(Threads REQUIRED)
  target_compile_definitions(xprobe-cupti PRIVATE XPROBE_HAS_CUPTI=1 _GNU_SOURCE)
  target_include_directories(xprobe-cupti SYSTEM PRIVATE "${XPROBE_CUPTI_INCLUDE_DIR}")
  target_link_libraries(xprobe-cupti PRIVATE "${XPROBE_CUPTI_LIBRARY}" Threads::Threads)
  get_filename_component(XPROBE_CUPTI_LIBRARY_DIR "${XPROBE_CUPTI_LIBRARY}" DIRECTORY)
  set_target_properties(
    xprobe-cupti
    PROPERTIES BUILD_RPATH "${XPROBE_CUPTI_LIBRARY_DIR}"
  )
  message(STATUS "Building xprobe CUPTI Agent with ${XPROBE_CUPTI_LIBRARY}")
else()
  message(STATUS "CUPTI development files not found; building ABI-only agent")
endif()

if(BUILD_TESTING)
  add_executable(xprobe-cupti-smoke tests/cupti_smoke.c)
  target_link_libraries(xprobe-cupti-smoke PRIVATE xprobe-cupti)
  add_test(NAME cupti-smoke COMMAND xprobe-cupti-smoke)
endif()
