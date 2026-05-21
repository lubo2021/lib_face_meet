cmake_minimum_required(VERSION 3.5)
project(face_meet CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
option(DISABLE_AUTHORIZATION_CHECK "Disable authorization check" OFF)

set(SRC_LIST
    src/aes_encryption.cpp
)

find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} ${SRC_LIST})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto)

if(DISABLE_AUTHORIZATION_CHECK)
    target_compile_definitions(${PROJECT_NAME} PUBLIC DISABLE_AUTHORIZATION_CHECK)
endif()

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
