
link_directories ("${PROJECT_BIN_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}/test/unity/include")

set (EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_NAME})

aux_source_directory(./ TEST_SOURCE_FILES)

add_executable(run_unittest unity/unity.c ${TEST_SOURCE_FILES})
target_link_libraries (run_unittest  ${EXTRA_LIBS})
