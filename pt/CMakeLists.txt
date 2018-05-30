cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)


add_compile_options("-Wall")
set ( CMAKE_C_FLAGS "-std=c11 -O3 -D_FILE_OFFSET_BITS=64 -g")
set ( CMAKE_CXX_FLAGS "-std=c++11 -O3 -D_FILE_OFFSET_BITS=64")

set(PT_SRC pt_decoder.cpp disassembler.cpp tnt_cache.cpp)

add_library(pt STATIC ${PT_SRC})
add_executable(run_pt run_pt.cpp)
target_link_libraries(run_pt pt msr capstone)

add_executable(test_disassemble test_disassemble.cpp)
target_link_libraries(test_disassemble pt capstone)

install(TARGETS pt run_pt test_disassemble
		RUNTIME DESTINATION bin
		ARCHIVE DESTINATION bin
)

