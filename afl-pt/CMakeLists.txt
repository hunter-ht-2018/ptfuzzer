set(PREFIX     /usr/local)
set(BIN_PATH    ${PREFIX}/bin)
set(HELPER_PATH ${PREFIX}/lib/afl)
set(DOC_PATH    ${PREFIX}/share/doc/afl)
set(MISC_PATH   ${PREFIX}/share/afl)
set ( CMAKE_C_FLAGS " -std=c11 -O3 -g -D_FILE_OFFSET_BITS=64 -Wall -D_FORTIFY_SOURCE=2 -Wno-pointer-sign -DAFL_PATH=\\\"${HELPER_PATH}\\\" -DDOC_PATH=\\\"${DOC_PATH}\\\" -DBIN_PATH=\\\"${BIN_PATH}\\\" ")
set ( CMAKE_CXX_FLAGS " -std=c++11 -O3 -g -fpermissive -D_FILE_OFFSET_BITS=64 -Wall -D_FORTIFY_SOURCE=2 -Wno-pointer-sign -DAFL_PATH=\\\"${HELPER_PATH}\\\" -DDOC_PATH=\\\"${DOC_PATH}\\\" -DBIN_PATH=\\\"${BIN_PATH}\\\" ")

include_directories(../pt)
include_directories(../msr)

set(SRC afl-ptfuzz.c)
add_executable(afl-ptfuzz ${SRC})
target_link_libraries(afl-ptfuzz pt msr capstone dl)

install(TARGETS afl-ptfuzz
		RUNTIME DESTINATION bin
)
