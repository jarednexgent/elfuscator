cmake_minimum_required(VERSION 3.0)
project(elfuscator C)

# Compiler flags (user can override with -DCMAKE_C_FLAGS)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -s -static -std=gnu11")

# Gather all .c source files under src/
file(GLOB SOURCES "src/*.c")

# Create the binary
add_executable(elfuscator ${SOURCES})

# Remove .comment section after build
add_custom_command(TARGET elfuscator POST_BUILD
    COMMAND ${CMAKE_STRIP} -R .comment $<TARGET_FILE:elfuscator>)