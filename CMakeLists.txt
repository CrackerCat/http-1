cmake_minimum_required(VERSION 3.19)

set(PACKAGE_NAME    "http")
set(PACKAGE_VERSION "0.1.0")
project(${PACKAGE_NAME}
	LANGUAGES CXX
	VERSION ${PACKAGE_VERSION}
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -W -fPIC")
set(CMAKE_VERBOSE_MAKEFILE ON)

#
# dependencies
#
find_package(OpenSSL "1.1.1" COMPONENTS Crypto SSL REQUIRED)
find_package(ZLIB)
include(ExternalProject)

# curl
set(LIBCURL_TAG "7_80_0")
message(STATUS "Using libcurl tag ${LIBCURL_TAG} --with-openssl=${OPENSSL_FOUND} --with-zlib=${ZLIB_FOUND}")
ExternalProject_Add(libcurl
        PREFIX cmake
        URL https://github.com/curl/curl/archive/refs/tags/curl-${LIBCURL_TAG}.tar.gz
        CONFIGURE_COMMAND autoreconf -fvi ${CMAKE_BINARY_DIR}/cmake/src/libcurl && ${CMAKE_BINARY_DIR}/cmake/src/libcurl/configure --prefix=${CMAKE_BINARY_DIR}/libcurl --with-openssl --with-zlib

        BUILD_COMMAND make -j8
        INSTALL_COMMAND make install
        UPDATE_COMMAND ""
        INSTALL_DIR ${CMAKE_BINARY_DIR}/libcurl
)

# http
add_library(${PROJECT_NAME} http.hxx http.cxx)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

add_dependencies(${PROJECT_NAME} libcurl)
target_include_directories(${PROJECT_NAME}
	PRIVATE "${CMAKE_SOURCE_DIR}"
	PRIVATE "${CMAKE_BINARY_DIR}/libcurl/include"
)
target_link_directories(${PROJECT_NAME}
	PRIVATE "${CMAKE_BINARY_DIR}/libcurl/lib"
)
target_link_libraries(${PROJECT_NAME}
	OpenSSL::SSL
	OpenSSL::Crypto
  ZLIB::ZLIB
	curl
)