cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)

IF(NOT PREFIX)
    set(CMAKE_INSTALL_PREFIX .)
ELSE()
    set(CMAKE_INSTALL_PREFIX ${PREFIX})
ENDIF()
add_compile_options("-Wall")

add_subdirectory(pt)
add_subdirectory(msr)
add_subdirectory(afl-pt)

install(FILES run_with_pt.py DESTINATION bin)
install(FILES ptfuzzer.py DESTINATION bin)

