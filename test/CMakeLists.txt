
link_directories ("${PROJECT_BIN_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}/test/unity/include")

set (EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_NAME})

add_executable(run_unittest unittest.c unity/unity.c)
target_link_libraries (run_unittest  ${EXTRA_LIBS})
