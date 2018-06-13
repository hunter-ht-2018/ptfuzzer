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
#include <sstream>
#include "tnt_cache.h"

#define BIT(x)				(1ULL << (x))
#define NOT_TAKEN			0
#define TAKEN				1
#define TNT_EMPTY			2

#define SHORT_TNT_OFFSET	1
#define SHORT_TNT_MAX_BITS	8-1-SHORT_TNT_OFFSET

#define LONG_TNT_OFFSET		16
#define LONG_TNT_MAX_BITS	64-1-LONG_TNT_OFFSET

static inline uint8_t asm_bsr(uint64_t x){
    __asm__("bsrq %0, %0" : "=r" (x) : "0" (x));
    return x;
}

static void free_tnt_cache(tnt_cache_t* self){
    tnt_cache_obj* tmp;
    tnt_cache_obj* new_tnt;
    if(self->head){
        new_tnt = self->head;
        tmp = NULL;
        while(new_tnt){
            tmp = new_tnt;
            new_tnt = new_tnt->next;
            free(tmp);
        }
        self->head = NULL;
        self->next_node = NULL;
    }
}

static inline void free_tnt_cache_obj(tnt_cache_t* self){
    tnt_cache_obj* tmp;
    tmp = self->head;
    self->head = self->head->next;
    free(tmp);
}

uint8_t process_tnt_cache(tnt_cache_t* self){
    uint8_t ret;
    if(self->head){
        /* Short TNT */
        if (self->head->bits <= SHORT_TNT_MAX_BITS){
            ret = !!(self->head->data & BIT((SHORT_TNT_OFFSET-1) + self->head->bits - self->head->processed));
        }
        /* Long TNT */
        else {
            ret = !!(self->head->data & BIT((LONG_TNT_OFFSET-1) + (self->head->bits - self->head->processed)));
        }

        self->counter--;
        self->head->processed++;

        /* Free this TNT cache object if consumed... */
        if (self->head->processed == self->head->bits){
            if(self->next_node == self->head){
                free_tnt_cache(self);
            }
            else {
                free_tnt_cache_obj(self);
            }
        }
        return ret;
    }

    /* TNT cache seems to be empty... */
    return TNT_EMPTY;
}

uint32_t count_tnt_bits(bool short_tnt, uint64_t data) {
    uint8_t bits = 0;
    if(short_tnt){
        /* Short TNT magic  */
        bits = asm_bsr(data)-SHORT_TNT_OFFSET;
    }
    else{
        /* Long TNT magic  */
        bits = asm_bsr(data)-LONG_TNT_MAX_BITS;
    }
    return bits;
}

std::string tnt_to_string(bool short_tnt, uint64_t data) {
    std::stringstream ss;
    uint32_t bits = count_tnt_bits(short_tnt, data);
    ss << bits << " ";
    for(uint32_t i = 0; i < bits; i ++) {
        uint8_t ret = !!(data & BIT((SHORT_TNT_OFFSET-1) + bits - i));
        if(ret) ss << "T";
        else ss << "N";
    }
    return ss.str();
}

void append_tnt_cache(tnt_cache_t* self, bool short_tnt, uint64_t data){
    tnt_cache_obj* new_tnt;
    uint8_t bits;

    if(short_tnt){
        /* Short TNT magic  */
        bits = asm_bsr(data)-SHORT_TNT_OFFSET;
    }
    else{
        /* Long TNT magic  */
        bits = asm_bsr(data)-LONG_TNT_MAX_BITS;
    }

    if (!bits){
        /* trailing 1 not found... */
        return;
    }

    new_tnt = (tnt_cache_obj*)malloc(sizeof(tnt_cache_obj));
    new_tnt->bits = bits;
    if(self->next_node){
        self->next_node->next = new_tnt;
    }
    else{
        self->head = new_tnt;
    }
    new_tnt->processed = 0;
    new_tnt->data = data;
    new_tnt->next = NULL;
    self->next_node = new_tnt;
    self->counter += bits;
}

bool is_empty_tnt_cache(tnt_cache_t* self){
    return (bool)!!(self->counter);
}

int count_tnt(tnt_cache_t* self){
    return self->counter;
}

tnt_cache_t* tnt_cache_init(void){
    tnt_cache_t* res = (tnt_cache_t*)malloc(sizeof(tnt_cache_t));
    res->head = NULL;
    res->next_node = NULL;
    res->counter = 0;
    return res;
}

tnt_cache_t* tnt_cache_reset(tnt_cache_t* res){
    tnt_cache_destroy(res);
    return tnt_cache_init();
}

void tnt_cache_destroy(tnt_cache_t* self){
    free_tnt_cache(self);
    free(self);
}

