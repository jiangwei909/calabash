cmake_minimum_required(VERSION 3.6)
project(calabash VERSION 0.8.0)

IF (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
ENDIF()

configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
)

include_directories ("${PROJECT_BINARY_DIR}")

include_directories ("${PROJECT_SOURCE_DIR}/include")

if (OPENSSL_ROOT)
  include_directories ("${OPENSSL_ROOT}/include")

  if (WIN32)
    set(SSL_SUB_DIR win)
  else()
    set(SSL_SUB_DIR linux)
  endif(WIN32)

  link_directories ("${OPENSSL_ROOT}/build/${SSL_SUB_DIR}")
  set (EXTRA_LIBS ${EXTRA_LIBS} crypto)
endif (OPENSSL_ROOT)


add_subdirectory (test)

add_library(calabash SHARED src/calabash.c src/utils.c src/des.c src/rsa.c src/encoding.c)
#target_link_libraries(calabash libcrypto)
target_link_libraries (${PROJECT_NAME}  ${EXTRA_LIBS})

# add the install targets
install (TARGETS ${PROJECT_NAME} DESTINATION lib)
install (DIRECTORY "${PROJECT_SOURCE_DIR}/include/calabash" DESTINATION include)
install (FILES "${PROJECT_SOURCE_DIR}/include/calabash.h"   DESTINATION include)
install (FILES "${PROJECT_BINARY_DIR}/config.h"        
         DESTINATION include/calabash)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE  
     "${CMAKE_CURRENT_SOURCE_DIR}/License.txt")
set (CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
include (CPack)