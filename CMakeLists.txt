cmake_minimum_required(VERSION 3.22)
project(face_meet CXX)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)


# 配置动态库的宏定义
OPTION(BUILD_SHARED_LIBS "Build using shared libraries" ON)

set(CMAKE_VERBOSE_MAKEFILE ON)
# 设置库的输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

ADD_DEFINITIONS(-fexec-charset=UTF-8 -finput-charset=UTF-8)
AUX_SOURCE_DIRECTORY(./src SRC_LIST)




INCLUDE_DIRECTORIES(/usr/include)
INCLUDE_DIRECTORIES(./include)
INCLUDE_DIRECTORIES()


#openssl
find_package(OpenSSL REQUIRED) 

# 创建共享库
add_library(${PROJECT_NAME} SHARED ${SRC_LIST})

# 链接外部库
target_link_libraries(${PROJECT_NAME}  PUBLIC  OpenSSL::Crypto)



