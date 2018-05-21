cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)

set(CMAKE_INSTALL_PREFIX .)

add_compile_options("-Wall")

add_subdirectory(pt)
add_subdirectory(msr)
add_subdirectory(afl-pt)

install(FILES run_with_pt.py DESTINATION bin)
install(FILES ptfuzzer.py DESTINATION bin)

