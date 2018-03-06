
set(PT_SRC pt.c)

add_library(pt STATIC ${PT_SRC})

add_executable(test_pt test_pt.cpp)
target_link_library(test_pt pt)
