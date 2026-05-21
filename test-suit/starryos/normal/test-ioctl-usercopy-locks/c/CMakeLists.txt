cmake_minimum_required(VERSION 3.20)

project(test_ioctl_usercopy_locks C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-ioctl-usercopy-locks src/main.c)
target_compile_options(test-ioctl-usercopy-locks PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-ioctl-usercopy-locks RUNTIME DESTINATION usr/bin)
