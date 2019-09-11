
link_directories ("${PROJECT_BINARY_DIR} ${OPENSSL_ROOT}")
include_directories ("${PROJECT_SOURCE_DIR}/test/unity/include")
message("lindir=${PROJECT_BINARY_DIR} ${OPENSSL_ROOT}")
set (EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_NAME})

aux_source_directory(./ TEST_SOURCE_FILES)
message("extra lib=${EXTRA_LIBS}")

add_executable(run_unittest unity/unity.c ${TEST_SOURCE_FILES})
target_link_libraries (run_unittest  ${EXTRA_LIBS})
