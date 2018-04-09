#ifndef _HF_LINUX_PERF_EXT_H_
#define _HF_LINUX_PERF_EXT_H_

#ifdef __cplusplus
extern "C"{
#endif
void init_pt_fuzzer(char* raw_bin_file, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point);
void start_pt_fuzzer(int pid);
void stop_pt_fuzzer(uint8_t *trace_bits);

void wrmsr_on_all_cpus(uint32_t reg, int valcnt, char *regvals[]);
void rdmsr_on_all_cpus(uint32_t reg);
#ifdef __cplusplus
}
#endif
#endif
