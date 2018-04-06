cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)


add_compile_options("-Wall")

add_subdirectory(pt)
add_subdirectory(msr)
