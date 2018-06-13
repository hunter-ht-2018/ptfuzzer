set ( CMAKE_C_FLAGS "-g -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
set ( CMAKE_CXX_FLAGS "-std=c++11 -D_FILE_OFFSET_BITS=64 -g")

set(MSR_SRC wrmsr.c rdmsr.c)

add_library(msr STATIC ${MSR_SRC})

install(TARGETS msr
		ARCHIVE DESTINATION .
)

