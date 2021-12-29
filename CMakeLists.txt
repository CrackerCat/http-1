cmake_minimum_required(VERSION 3.4)

project(http
  LANGUAGES C
  VERSION "0.1.0")
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_STANDARD 11)

if (MSVC)
  # Use secure functions by default and suppress warnings about "deprecated" functions
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_NONSTDC_NO_WARNINGS=1 /D _CRT_SECURE_NO_WARNINGS=1")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
        "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
        "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif (MSVC)

option(CMAKE_DISABLE_TESTING "Disable test creation" OFF)
option(CMAKE_ENABLE_SANITIZERS "Enable http sanitizers" OFF)
option(HTTP_STATIC_PIC "Build static http with PIC" ON)

#
# dependencies
#
find_package(OpenSSL "1.1.1" COMPONENTS Crypto SSL REQUIRED)
include(ExternalProject)

# curl
set(LIBCURL_TAG "7_80_0")
message(STATUS "Using libcurl tag ${LIBCURL_TAG} --with-openssl=${OPENSSL_ROOT_DIR}")
ExternalProject_Add(libcurl
        PREFIX cmake
        URL https://github.com/curl/curl/archive/refs/tags/curl-${LIBCURL_TAG}.tar.gz
        CONFIGURE_COMMAND autoreconf -fvi ${CMAKE_BINARY_DIR}/cmake/src/libcurl && ${CMAKE_BINARY_DIR}/cmake/src/libcurl/configure --prefix=${CMAKE_BINARY_DIR}/libcurl --with-openssl=${OPENSSL_ROOT_DIR}

        BUILD_COMMAND make -j8
        INSTALL_COMMAND make install
        UPDATE_COMMAND ""
        INSTALL_DIR ${CMAKE_BINARY_DIR}/libcurl
)

# http
set(SRC src/http.h src/http.c)

add_library(${PROJECT_NAME} ${SRC})
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

if(HTTP_STATIC_PIC)
  set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY C_VISIBILITY_PRESET hidden)
if(BUILD_SHARED_LIBS)
  target_compile_definitions(${PROJECT_NAME}
    PUBLIC HTTP_SHARED
    PRIVATE HTTP_BUILD_SHARED
  )
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>
)

