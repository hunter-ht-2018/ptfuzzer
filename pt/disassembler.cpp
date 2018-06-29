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
#include <map>
#include <iostream>
#include <assert.h>
#include "disassembler.h"


my_cofi_map::my_cofi_map(uint64_t base_address, uint32_t code_size) : base_address(base_address), code_size(code_size) {
    assert(code_size < 100 * 1024 * 1024);
    map_data = (cofi_inst_t**)malloc(sizeof(cofi_inst_t*) * code_size);
    memset(map_data, 0, sizeof(cofi_inst_t*) * code_size);
}

my_cofi_map::~my_cofi_map() {
    free(map_data);
}

void my_cofi_map::set_decode_info(uint64_t decoded_addr, uint64_t dsize) {
    //TODO: implement it.
    this->decoded_size += dsize;
}

static cofi_type get_inst_type(cs_insn *ins){
    uint8_t i, j;
    cs_x86 details = ins->detail->x86;

    for (i = 0; i < LOOKUP_TABLES; i++){
        for (j = 0; j < lookup_table_sizes[i]; j++){
            if (ins->id == lookup_tables[i][j].opcode){

                /* check MOD R/M */
                if (lookup_tables[i][j].modrm != IGN_MOD_RM && lookup_tables[i][j].modrm != (details.modrm & MODRM_AND))
                    continue;

                /* check opcode prefix byte */
                if (lookup_tables[i][j].opcode_prefix != IGN_OPODE_PREFIX && lookup_tables[i][j].opcode_prefix != details.opcode[0])
                    continue;
#ifdef DEBUG
                /* found */
                //printf("%lx (%d)\t%s\t%s\t\t", ins->address, i, ins->mnemonic, ins->op_str);
                //print_string_hex("      \t", ins->bytes, ins->size);
#endif
                return (cofi_type)i;

            }
        }
    }
    return NO_COFI_TYPE;
}

static void print_inst(cs_insn* insn) {
    char byte_str[64];
    for(int i = 0; i < insn->size; i ++) {
        sprintf(byte_str + i * 3, "%02x ", insn->bytes[i]);
    }
    printf("%lx:\t%-32s\t%s\t%s\t\t\n", insn->address, byte_str, insn->mnemonic, insn->op_str);
}



uint32_t disassemble_binary(const uint8_t* code, uint64_t base_address, uint64_t& code_size, cofi_map_t& cofi_map){
    csh handle;
    cs_insn *insn;
    cofi_type type;
    uint64_t num_inst = 0;
    uint64_t num_cofi_inst = 0;

    uint64_t max_address = base_address + code_size;

    uint64_t address = base_address;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    insn = cs_malloc(handle);

    cofi_inst_t* current_cofi = nullptr;
    cofi_inst_t* pre_cofi = nullptr;

    uint64_t bb_start_addr;
    const uint8_t* org_code = code;
    const size_t org_code_size = code_size;
    while(cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
        if (insn->address > max_address){
            break;
        }
        if(cofi_map.contains(insn->address)) break; //already decoded.
        type = get_inst_type(insn);
#ifdef DEBUG
        //printf("%lx:\t(%d)\t%s\t%s\t\t\n", insn->address, type, insn->mnemonic, insn->op_str);
        print_inst(insn);
#endif
        num_inst ++;

        if(current_cofi == nullptr) {
            current_cofi =  new cofi_inst_t;
            current_cofi->bb_start_addr = insn->address;
        }
        if(pre_cofi != nullptr) {
            if(pre_cofi->next_cofi == nullptr) {
                pre_cofi->next_cofi = current_cofi;
            }
        }

        if (type != NO_COFI_TYPE){
            num_cofi_inst ++;
            current_cofi->inst_addr = insn->address;
            current_cofi->type = get_inst_type(insn);
            if (type == COFI_TYPE_CONDITIONAL_BRANCH || type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH){
                current_cofi->target_addr = hex_to_bin(insn->op_str);
            }
            else {
                current_cofi->target_addr = 0;
            }
            current_cofi->next_cofi = nullptr;
            cofi_map[insn->address] = current_cofi;
            pre_cofi = current_cofi;
            current_cofi = nullptr;
        }
        else {
            cofi_map[insn->address] = current_cofi;
        }
    }

    uint64_t decoded_size = org_code_size - code_size;
    cofi_map.set_decode_info(base_address, decoded_size);
    //std::cout << "disassmble: undecoded size is: " << code_size << std::endl;
    cs_free(insn, 1);
    cs_close(&handle);
    return num_cofi_inst;
}
