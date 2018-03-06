cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)


# This is a C++11 library
add_compile_options("-std=c++11")
add_compile_options("-Wall")
add_compile_options("-D_FILE_OFFSET_BITS=64")
add_compile_options("-g")

add_subdirectory(pt)
