cmake_minimum_required(VERSION 3.5)
project(face_meet CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

set(SRC_LIST
    src/aes_encryption.cpp
)

include(ExternalProject)

set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl_install)

if(WIN32)
    ExternalProject_Add(openssl_ext
        URL https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz
        URL_HASH SHA256=23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533
        CONFIGURE_COMMAND perl Configure VC-WIN64A no-shared --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}/ssl
        BUILD_COMMAND nmake
        INSTALL_COMMAND nmake install_sw
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS
            ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib
    )
    set(OPENSSL_LIB ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
    set(OPENSSL_DEP_LIBS "")
else()
    ExternalProject_Add(openssl_ext
        URL https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz
        URL_HASH SHA256=23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533
        CONFIGURE_COMMAND ./config no-shared --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}/ssl
        BUILD_COMMAND make
        INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS
            ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a
    )
    set(OPENSSL_LIB ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
    set(OPENSSL_DEP_LIBS "")
endif()

add_library(OpenSSL::Crypto STATIC IMPORTED)
set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION ${OPENSSL_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INSTALL_DIR}/include
)
add_dependencies(OpenSSL::Crypto openssl_ext)

add_library(${PROJECT_NAME} ${SRC_LIST})
add_dependencies(${PROJECT_NAME} openssl_ext)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
