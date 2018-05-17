cmake_minimum_required(VERSION 2.8)
project(calabash)

IF (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
ENDIF()

IF (WIN32) 
    add_definitions(-DWIN32)
ENDIF()

add_definitions(-Wall)

include_directories(${OPENSSL_INCLUDE_PATH} unity)
link_directories(${calabash_SOURCE_DIR}/libs/win)

add_library(calabash SHARED calabash.c)
target_link_libraries(calabash libcrypto)

#add_executable(tinygmca ${SOURCE_FILES} )
add_executable(unittest unittest.c calabash.c unity/unity.c unity/unity.h)
target_link_libraries(unittest libcrypto)
