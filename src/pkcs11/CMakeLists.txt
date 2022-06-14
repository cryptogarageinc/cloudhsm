cmake_minimum_required(VERSION 3.12)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
if(NOT WIN32)
set(TARGET_RPATH "" CACHE STRING "target rpath list (separator is ';') (default:)")
else()
set(TARGET_RPATH "")
endif()


####################
# common setting
####################
set(WORK_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR}/${WORK_BINARY_DIR_NAME})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR}/${WORK_BINARY_DIR_NAME})

if(NOT WIN32)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
endif()
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
set(CMAKE_INSTALL_RPATH "${TARGET_RPATH};./;./build/Release;/usr/local/lib;/usr/local/lib64;@rpath")
else()
set(CMAKE_INSTALL_RPATH "./;./build/Release;/usr/local/lib;/usr/local/lib64;@rpath")
endif()
endif()


####################
# project setting
####################
project(cloudhsmpkcs11util C)

if(ENABLE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()

target_sources(${PROJECT_NAME}
  PRIVATE
    common.c pkcs11.c common.h ec_sign.c sign.h attributes.c attributes.h find_objects.c
)
target_link_libraries(${PROJECT_NAME} dl)


####################
# install & export
####################
include(GNUInstallDirs)

install(TARGETS       ${PROJECT_NAME}
        EXPORT        ${PROJECT_NAME}-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

export(TARGETS ${PROJECT_NAME}
       APPEND FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-export.cmake
       EXPORT_LINK_INTERFACE_LIBRARIES)

# install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/pkcs11"
#         DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
#         FILES_MATCHING PATTERN "*.h")
