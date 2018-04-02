set ( CMAKE_C_FLAGS "-std=c11 -D_FILE_OFFSET_BITS=64 -g")
set ( CMAKE_CXX_FLAGS "-std=c++11 -D_FILE_OFFSET_BITS=64 -g")

set(PT_SRC pt.c disassembler.cpp tnt_cache.c)

add_library(pt STATIC ${PT_SRC})
add_executable(test_pt test_pt.c)
target_link_libraries(test_pt pt capstone)

add_executable(test_disassemble test_disassemble.cpp)
target_link_libraries(test_disassemble pt capstone)

