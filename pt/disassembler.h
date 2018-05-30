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

//~ #include "qemu/osdep.h"
#include "khash.h"
#include "tnt_cache.h"

KHASH_MAP_INIT_INT(ADDR0, uint64_t)

typedef struct{
	uint16_t opcode;
	uint8_t modrm;
	uint8_t opcode_prefix;
} cofi_ins;

typedef enum cofi_types{
	COFI_TYPE_CONDITIONAL_BRANCH, 
	COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH, 
	COFI_TYPE_INDIRECT_BRANCH, 
	COFI_TYPE_NEAR_RET, 
	COFI_TYPE_FAR_TRANSFERS,
	NO_COFI_TYPE
} cofi_type;


typedef struct {
	uint64_t ins_addr;
	uint64_t target_addr;
	cofi_type type;
} cofi_header;

typedef struct cofi_list {
	struct cofi_list *list_ptr;
	struct cofi_list *cofi_ptr;
	cofi_header *cofi;
} cofi_list;

typedef struct disassembler_s{
	uint8_t* code;
	uint64_t min_addr;
	uint64_t max_addr;
	uint64_t entry_point;
	void (*handler)(uint64_t);
	//khash_t(ADDR0) *map;
	uint64_t *map;
	cofi_list* list_head;
	cofi_list* list_element;
	bool debug;
	bool is_decode;


} disassembler_t;

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
public:
	my_cofi_map(uint64_t base_address, uint32_t code_size) : base_address(base_address), code_size(code_size) {
		map_data = (cofi_inst_t**)malloc(sizeof(cofi_inst_t*) * code_size);
	}
	~my_cofi_map() {
		free(map_data);
	}
	inline cofi_inst_t*& operator [](uint64_t addr) {
		return map_data[addr-base_address];
	}
};

typedef std::map<uint64_t, cofi_inst_t*> cofi_map_t;

disassembler_t* init_disassembler(uint8_t* code, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point, void (*handler)(uint64_t));
bool reset_disassembler(disassembler_t* self);
bool trace_disassembler(disassembler_t* self, uint64_t entry_point, bool isr, tnt_cache_t* tnt_cache_state);
void destroy_disassembler(disassembler_t* self);
void free_list(cofi_list* head);

uint32_t disassemble_binary(const uint8_t* code, uint64_t base_address, uint64_t max_address, cofi_map_t& cofi_map);
#endif
