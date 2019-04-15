cmake_minimum_required(VERSION 2.8)
project(calabash)

IF (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
ENDIF()

IF (WIN32) 
  add_definitions(-DWIN32)
  set(OS_OPENSSL_DIR win)
ELSE()
  set(OS_OPENSSL_DIR linux)
ENDIF()

#add_definitions(-Wall)

include_directories(${OPENSSL_INCLUDE_PATH} unity)
link_directories(${calabash_SOURCE_DIR}/libs/${OS_OPENSSL_DIR})

add_library(calabash SHARED calabash.c internal.c des.c rsa.c encoding.c)
#target_link_libraries(calabash libcrypto)
target_link_libraries(calabash crypto)

#add_executable(tinygmca ${SOURCE_FILES} )
add_executable(unittest unittest.c calabash.c unity/unity.c
  unity/unity.h internal.c des.c rsa.c encoding.c)
#target_link_libraries(unittest libcrypto)
target_link_libraries(unittest crypto)
