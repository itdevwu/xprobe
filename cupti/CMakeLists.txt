add_library(xprobe-cupti SHARED src/cupti_agent.c)

target_include_directories(
  xprobe-cupti
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)
target_compile_features(xprobe-cupti PRIVATE c_std_11)
target_compile_options(xprobe-cupti PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(xprobe-cupti PROPERTIES OUTPUT_NAME xprobe-cupti)

if(BUILD_TESTING)
  add_executable(xprobe-cupti-smoke tests/cupti_smoke.c)
  target_link_libraries(xprobe-cupti-smoke PRIVATE xprobe-cupti)
  add_test(NAME cupti-smoke COMMAND xprobe-cupti-smoke)
endif()

