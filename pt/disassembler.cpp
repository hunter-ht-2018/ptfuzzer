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
#include <string.h>
#include "disassembler.h"
#define LOOKUP_TABLES           5
#define IGN_MOD_RM                      0
#define IGN_OPODE_PREFIX        0
#define MODRM_REG(x)            (x << 3)
#define MODRM_AND                       0b00111000

/* http://stackoverflow.com/questions/29600668/what-meaning-if-any-does-the-mod-r-m-byte-carry-for-the-unconditional-jump-ins */
/* conditional branch */
cofi_ins cb_lookup[] = {
        {X86_INS_JAE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JA,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JBE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JB,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JCXZ,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JECXZ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JE,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JGE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JG,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JLE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JL,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNO,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNP,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNS,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JO,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JP,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JRCXZ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JS,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOP,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOPE,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOPNE,        IGN_MOD_RM,     IGN_OPODE_PREFIX},
};

/* unconditional direct branch */
cofi_ins udb_lookup[] = {
        {X86_INS_JMP,           IGN_MOD_RM,     0xe9},
        {X86_INS_JMP,           IGN_MOD_RM, 0xeb},
        {X86_INS_CALL,          IGN_MOD_RM,     0xe8},
};

/* indirect branch */
cofi_ins ib_lookup[] = {
        {X86_INS_JMP,           MODRM_REG(4),   0xff},
        {X86_INS_CALL,          MODRM_REG(2),   0xff},
};

/* near ret */
cofi_ins nr_lookup[] = {
        {X86_INS_RET,           IGN_MOD_RM,     0xc3},
        {X86_INS_RET,           IGN_MOD_RM,     0xc2},
};

/* far transfers */ 
cofi_ins ft_lookup[] = {
        {X86_INS_INT3,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INT,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INT1,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INTO,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRET,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRETD,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRETQ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JMP,           IGN_MOD_RM,             0xea},
        {X86_INS_JMP,           MODRM_REG(5),   0xff},
        {X86_INS_CALL,          IGN_MOD_RM,             0x9a},
        {X86_INS_CALL,          MODRM_REG(3),   0xff},
        {X86_INS_RET,           IGN_MOD_RM,             0xcb},
        {X86_INS_RET,           IGN_MOD_RM,             0xca},
        {X86_INS_SYSCALL,       IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSENTER,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSEXIT,       IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSRET,        IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_VMLAUNCH,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_VMRESUME,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
};

uint16_t cmp_lookup[] = {
        X86_INS_CMP,
        X86_INS_CMPPD,
        X86_INS_CMPPS,
        X86_INS_CMPSB,
        X86_INS_CMPSD,
        X86_INS_CMPSQ,
        X86_INS_CMPSS,
        X86_INS_CMPSW,
        X86_INS_CMPXCHG16B,
        X86_INS_CMPXCHG,
        X86_INS_CMPXCHG8B,
};

cofi_ins* lookup_tables[] = {
        cb_lookup,
        udb_lookup,
        ib_lookup,
        nr_lookup,
        ft_lookup,
};

uint8_t lookup_table_sizes[] = {
        22,
        3,
        2,
        2,
        19
};

static inline uint64_t fast_strtoull(const char *hexstring){
    uint64_t result = 0;
    uint8_t i = 0;
    if (hexstring[1] == 'x' || hexstring[1] == 'X')
        i = 2;
    for (; hexstring[i]; i++)
        result = (result << 4) + (9 * (hexstring[i] >> 6) + (hexstring[i] & 017));
    return result;
}

static inline uint64_t hex_to_bin(char* str){
    //return (uint64_t)strtoull(str, NULL, 16);
    return fast_strtoull(str);
}

my_cofi_map::my_cofi_map(uint64_t base_address, uint32_t code_size) : i_cofi_map(base_address, code_size)  {
    assert(code_size < 100 * 1024 * 1024);
    //map_data = (cofi_inst_t**)malloc(sizeof(cofi_inst_t*) * code_size);
    //memset(map_data, 0, sizeof(cofi_inst_t*) * code_size);
    map_data = new cofi_inst_t*[code_size]{nullptr};
}

my_cofi_map::~my_cofi_map() {
    //free(map_data);
    if(map_data != nullptr) delete map_data;
}

void i_cofi_map::set_decode_info(uint64_t decoded_addr, uint64_t dsize) {
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
            cofi_map.set(insn->address, current_cofi);
            pre_cofi = current_cofi;
            current_cofi = nullptr;
        }
        else {
            cofi_map.set(insn->address, current_cofi);
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return num_cofi_inst;
}
