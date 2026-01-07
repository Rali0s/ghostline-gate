cmake_minimum_required(VERSION 3.10)
project(packetlab_proxy CXX)

set(CAMKE_CXX_STANDARD 11)
SET(CMAKE_STANDARD_REQUIRED ON)

add_executable(packetlab_proxy
	src/main.cpp
	src/linux_epoll_proxy.cpp
)

target_include_directories(packetlab_proxy PRIVATE include)

# Helpful warnings
target_compile_options(packetlab_proxy PRIVATE -Wall -Wextra -Wpedantic)
