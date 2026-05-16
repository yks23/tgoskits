cmake_minimum_required(VERSION 3.20)
project(bug-ppoll-user-buffer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(bug-ppoll-user-buffer src/main.c)
target_compile_options(bug-ppoll-user-buffer PRIVATE -Wall -Wextra -Werror)

install(TARGETS bug-ppoll-user-buffer RUNTIME DESTINATION usr/bin)
