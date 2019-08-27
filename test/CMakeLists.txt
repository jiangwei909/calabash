
link_directories ("${PROJECT_BIN_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}/test/unity/include")

set (EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_NAME})

add_executable(runtest unittest.c unity/unity.c)
target_link_libraries (runtest  ${EXTRA_LIBS})


# #add_executable(tinygmca ${SOURCE_FILES} )
# add_executable(unittest unittest.c calabash.c unity/unity.c
#   unity/unity.h internal.c des.c rsa.c encoding.c)
# #target_link_libraries(unittest libcrypto)
# target_link_libraries(unittest crypto)