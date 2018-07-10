#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include "disassembler.h"


uint64_t min_addr_cle = 0ULL;
uint64_t max_addr_cle = 0ULL;
uint64_t entry_point_cle = 0ULL;
uint8_t* raw_bin_buf;

bool read_min_max()
{
    FILE *fp;
    int MAX_LINE_T = 1024;
    char strLine[MAX_LINE_T];
    char* endptr;

    min_addr_cle = 0ULL;
    max_addr_cle = 0ULL;
    entry_point_cle = 0ULL;

    if((fp = fopen("./min_max.txt","r")) == NULL)
    {
        return false;
    }
    fgets(strLine,MAX_LINE_T,fp);
    min_addr_cle = strtoull(strLine, &endptr, 10);
    fgets(strLine,MAX_LINE_T,fp);
    max_addr_cle = strtoull(strLine, &endptr, 10);
    fgets(strLine,MAX_LINE_T,fp);
    entry_point_cle = strtoull(strLine, &endptr, 10);
    fclose(fp);

    if(min_addr_cle == 0ULL || max_addr_cle == 0ULL || entry_point_cle == 0ULL)
    {
        printf("Error: min max addr = 0\n");
        return false;
    }
    return true;
}

bool read_raw_bin()
{
    FILE* pt_file = fopen("./raw_bin", "rb");

    raw_bin_buf = (uint8_t*)malloc(max_addr_cle - min_addr_cle);
    memset(raw_bin_buf, 0, max_addr_cle - min_addr_cle);

    if(NULL == pt_file)
    {
        return false;
    }

    int count;
    while (!feof (pt_file))
    {
        count = fread (raw_bin_buf, sizeof(uint8_t), max_addr_cle - min_addr_cle, pt_file);
    }
    fclose(pt_file);
    return true;
}

int main (int argc, char** argv) {
    if(!read_min_max()){
        std::cerr << "read min and max addr failed." << std::endl;
    }

    if(!read_raw_bin()){
        std::cerr << "read raw binary failed." << std::endl;
    }
    cofi_map_t cofi_map(min_addr_cle, max_addr_cle-min_addr_cle);
    uint32_t num_cofi_inst = disassemble_binary(raw_bin_buf, min_addr_cle, max_addr_cle, cofi_map);
    uint64_t addr_start = min_addr_cle;
    cofi_inst_t* head = cofi_map.get(addr_start);
    while(head == nullptr) {
        addr_start ++;
        head = cofi_map.get(addr_start);
    }
    std::cout << "first address contain cofi is : " << addr_start << std::endl;
    while(head != nullptr) {
        std::cout << std::hex << head->inst_addr << " -> " << head->target_addr << std::endl;
        head = head->next_cofi;
    }
    std::cout << "number of cofi inst: " << num_cofi_inst << std::endl;
    return 0;
}
