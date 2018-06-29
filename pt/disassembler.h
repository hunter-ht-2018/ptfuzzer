/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

 */

#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <string>

#include "tnt_cache.h"

typedef enum cofi_types{
    COFI_TYPE_CONDITIONAL_BRANCH,
    COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH,
    COFI_TYPE_INDIRECT_BRANCH,
    COFI_TYPE_NEAR_RET,
    COFI_TYPE_FAR_TRANSFERS,
    NO_COFI_TYPE
} cofi_type;


//#define DEBUG_COFI_INST
typedef struct _cofi_inst_t {
    cofi_type type;
    uint64_t bb_start_addr;
    uint64_t inst_addr;
    uint64_t target_addr;
    struct _cofi_inst_t* next_cofi;
#ifdef DEBUG_COFI_INST
    std::string dis_inst;
#endif
} cofi_inst_t;

class my_cofi_map {
    cofi_inst_t** map_data;
    uint64_t base_address;
    uint32_t code_size;
    uint32_t decoded_size = 0;
public:
    my_cofi_map(uint64_t base_address, uint32_t code_size);
    ~my_cofi_map();
    inline cofi_inst_t*& operator [](uint64_t addr) {
        return map_data[addr-base_address];
    }
    bool contains(uint64_t addr) {
        return map_data[addr-base_address] != nullptr;
    }
    inline void set(uint64_t addr, cofi_inst_t* cofi_obj) { map_data[addr-base_address] = cofi_obj; }
    inline cofi_inst_t* get(uint64_t addr) { return map_data[addr-base_address]; }
    void set_decode_info(uint64_t decoded_addr, uint64_t decoded_size);
    double complete_percentage() { return (double) decoded_size * 100 / code_size; }
};

//typedef std::map<uint64_t, cofi_inst_t*> cofi_map_t;
typedef my_cofi_map cofi_map_t;
uint32_t disassemble_binary(const uint8_t* code, uint64_t base_address, uint64_t& code_size, cofi_map_t& cofi_map);
#endif
