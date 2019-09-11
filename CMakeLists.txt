cmake_minimum_required(VERSION 3.6)
project(calabash VERSION 0.8.0)

IF (CMAKE_BUILD_TYPE MATCHES "Debug")
  add_definitions(-DDEBUG -Wall)
  SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
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
    set (EXTRA_LIBS ${EXTRA_LIBS} libcrypto)
  else()
    set (EXTRA_LIBS ${EXTRA_LIBS} crypto)
  endif(WIN32)

  link_directories ("${OPENSSL_ROOT}/")
  
endif (OPENSSL_ROOT)

add_subdirectory (test)

aux_source_directory(src/ SOURCE_FILES)

add_library(calabash SHARED ${SOURCE_FILES})

#target_link_libraries(calabash libcrypto)
target_link_libraries (${PROJECT_NAME}  ${EXTRA_LIBS})

# add a target to generate API documentation with Doxygen
 
FIND_PACKAGE(Doxygen)
OPTION(BUILD_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})
 
IF(BUILD_DOCUMENTATION)
    IF(NOT DOXYGEN_FOUND)
        MESSAGE(FATAL_ERROR "Doxygen is needed to build the documentation.")
    ENDIF()
 
    SET(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    SET(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
 
    CONFIGURE_FILE(${doxyfile_in} ${doxyfile} @ONLY)
 
    ADD_CUSTOM_TARGET(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
 
    INSTALL(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
ENDIF()

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
