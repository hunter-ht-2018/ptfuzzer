

#ifndef _HF_LINUX_PERF_H_
#define _HF_LINUX_PERF_H_
#define _GNU_SOURCE

//~ #include <dirent.h>
#include <inttypes.h>
#include <limits.h>
//~ #include <pthread.h>
#include <stdbool.h>
//~ #include <stdint.h>
//~ #include <sys/param.h>
//~ #include <sys/queue.h>
//~ #include <sys/types.h>
//~ #include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
//~ #include <inttypes.h>
//~ #include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
//~ #include <linux/sysctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
//~ #include <sys/mman.h>
//~ #include <sys/poll.h>
//~ #include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <wait.h>

#include "disassembler.h"
//~ #include "tnt_cache.h"

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 8192
#define _HF_PERF_MAP_SZ (1024 * 512)
#define _HF_PERF_AUX_SZ (1024 * 1024)
#define _HF_PERF_BITMAP_SIZE_16M (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7ffffff

////////AFL bitmap
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
///////

#define LEFT(x) ((end - p) >= (x))
#define BIT(x) (1U << (x))

#define BENCHMARK 				1


//++++++++++++++++++++++++++++++++++++++
//++++++++++++++++++++++++++++++++++++++

#define PT_PKT_TSC_LEN		8
#define PT_PKT_TSC_BYTE0	0b00011001

#define PT_PKT_MTC_LEN		2
#define PT_PKT_MTC_BYTE0	0b01011001

//++++++++++++++++++++++++++++++++++++++
//++++++++++++++++++++++++++++++++++++++



#define PT_PKT_GENERIC_LEN		2
#define PT_PKT_GENERIC_BYTE0	0b00000010

#define PT_PKT_LTNT_LEN			8
#define PT_PKT_LTNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_LTNT_BYTE1		0b10100011

#define PT_PKT_PIP_LEN			8
#define PT_PKT_PIP_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PIP_BYTE1		0b01000011

#define PT_PKT_CBR_LEN			4
#define PT_PKT_CBR_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_CBR_BYTE1		0b00000011

#define PT_PKT_OVF_LEN			8
#define PT_PKT_OVF_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_OVF_BYTE1		0b11110011

#define PT_PKT_PSB_LEN			16
#define PT_PKT_PSB_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSB_BYTE1		0b10000010

#define PT_PKT_PSBEND_LEN		2
#define PT_PKT_PSBEND_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSBEND_BYTE1		0b00100011

#define PT_PKT_MNT_LEN			11
#define PT_PKT_MNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_MNT_BYTE1		0b11000011
#define PT_PKT_MNT_BYTE2		0b10001000

#define PT_PKT_TMA_LEN			7
#define PT_PKT_TMA_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_TMA_BYTE1		0b01110011

#define PT_PKT_VMCS_LEN			7
#define PT_PKT_VMCS_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_VMCS_BYTE1		0b11001000

#define	PT_PKT_TS_LEN			2
#define PT_PKT_TS_BYTE0			PT_PKT_GENERIC_BYTE0
#define PT_PKT_TS_BYTE1			0b10000011

#define PT_PKT_MODE_LEN			2
#define PT_PKT_MODE_BYTE0		0b10011001

#define PT_PKT_TIP_LEN			8
#define PT_PKT_TIP_SHIFT		5
#define PT_PKT_TIP_MASK			0b00011111
#define PT_PKT_TIP_BYTE0		0b00001101
#define PT_PKT_TIP_PGE_BYTE0	0b00010001
#define PT_PKT_TIP_PGD_BYTE0	0b00000001
#define PT_PKT_TIP_FUP_BYTE0	0b00011101

typedef struct {
    uint64_t newBBCnt;
}hwcnt_t;

typedef struct decoder_s{
	uint8_t* code;
	uint64_t min_addr;
    uint64_t max_addr;
	uint64_t entry_point;
	void (*handler)(uint64_t);
	uint64_t last_tip;
	uint64_t last_ip2;
	bool fup_pkt;
	bool isr;
	bool in_range;
	bool pge_enabled;
	disassembler_t* disassembler_state;
    tnt_cache_t* tnt_cache_state;
    bool is_decode;

} decoder_t;

typedef struct {
    pid_t pid;
    pid_t persistentPid;
    uint64_t pc;
    uint64_t backtrace;
    uint64_t access;
    int exception;
    char report[_HF_REPORT_SIZE];
    bool mainWorker;
    int persistentSock;
    bool tmOutSignaled;

    struct {
        /* For Linux code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        hwcnt_t hwCnts;
        pid_t attachedPid;
        int cpuIptBtsFd;
    }linux_t;
    
    decoder_t* decoder;
}run_t;

typedef enum {
    _HF_DYNFILE_NONE = 0x0,
    _HF_DYNFILE_INSTR_COUNT = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_BTS_EDGE = 0x10,
    _HF_DYNFILE_IPT_BLOCK = 0x20,
    _HF_DYNFILE_SOFT = 0x40,
}dynFileMethod_t;


bool perf_config(pid_t pid, run_t* run);
bool perf_init();
bool perf_open(pid_t pid, run_t* run);
void perf_close(run_t* run);
bool perf_enable(run_t* run);
bool perf_analyze(run_t* run);
bool perf_create(run_t* run, pid_t pid, dynFileMethod_t method, int* perfFd);
bool perf_reap(run_t* run);
bool perf_mmap_parse(run_t* run);
bool perf_mmap_reset(run_t* run);
void pt_bitmap(uint64_t addr);
bool pt_analyze(run_t* run);
decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point, void (*handler)(uint64_t));
tnt_cache_t* pt_decoder_reset(decoder_t* self);
void decode_buffer(decoder_t* self, uint8_t* map, size_t len, run_t* run);
void pt_decoder_destroy(decoder_t* self);
void pt_decoder_flush(decoder_t* self);
void print_bitmap();
uint8_t* get_trace_bits();

typedef struct binary_info_t {
	uint8_t* code;
	uint64_t base_address;
	uint64_t max_address;
	uint64_t entry_point;
};

class pt_packet_decoder{
	uint64_t min_address;
	uint64_t max_address;
	uint64_t last_tip = 0;
	uint64_t last_ip2 = 0;
	bool fup_pkt = false;
	bool isr = false;
	bool in_range = false;
	tnt_cache_t* tnt_cache_state = nullptr;
	bool pge_enabled = false;
	uint64_t aux_head;
	uint64_t aux_tail;
	uint8_t* pt_packets;

	cofi_map_t& cofi_map;
	uint64_t bitmap_last_ip = 0;
	uint8_t* trace_bits;
public:
	pt_packet_decoder(uint8_t* perf_pt_header, uint8_t* perf_pt_aux, cofi_map_t& map, uint64_t min_address, uint64_t max_address);
	void decode();
private:
	uint64_t get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip);
	inline void tip_handler(uint8_t** p, uint8_t** end){
		if (count_tnt(this->tnt_cache_state)){
			decode_tnt(this->last_tip);
		}
		this->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
	}

	inline void tip_pge_handler(uint8_t** p, uint8_t** end){
		this->pge_enabled = true;
		this->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
		//trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
	}

	inline void tip_pgd_handler(uint8_t** p, uint8_t** end){
		this->pge_enabled = false;
		if (count_tnt(this->tnt_cache_state)){
			decode_tnt(this->last_tip);
		}
		this->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
	}
	inline void tip_fup_handler(uint8_t** p, uint8_t** end){
		if (count_tnt(this->tnt_cache_state)){
			decode_tnt(this->last_tip);
		}
		this->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
	}
	inline void psb_handler(uint8_t** p){
		(*p) += PT_PKT_PSB_LEN;
		flush();
	}

	inline void long_tnt_handler(uint8_t** p){
		if (this->pge_enabled)
	        append_tnt_cache(tnt_cache_state, false, (uint64_t)*p);
		(*p) += PT_PKT_LTNT_LEN;
	}

	inline bool out_of_bounds(uint64_t addr) {
		if(addr < this->min_address || addr > this->max_address)
			return true;
		return false;
	}

	void flush();
	uint32_t decode_tnt(uint64_t entry_point);
	inline void alter_bitmap(uint64_t addr) {
		//64位地址截断为16位
	    uint16_t last_ip16, addr16, pos16;
	    last_ip16 = (uint16_t)(bitmap_last_ip);
	    addr16 = (uint16_t)(addr);
	    pos16 = (uint16_t)(last_ip16 ^ addr16);
	    trace_bits[pos16]++;
	    bitmap_last_ip = addr >> 1;
	}
};


class pt_tracer {
	uint8_t* perf_pt_header;
	uint8_t* perf_pt_aux;
	int trace_pid;
	int perf_fd = -1;
	//pt_decode_info_t decode_info;
public:
	pt_tracer(int pid) ;
	bool open_pt(int pt_perf_type);
	bool start_trace();
	bool stop_trace();
	bool close_pt();
};

class pt_fuzzer {
	std::string raw_binary_file;
	uint64_t base_address;
	uint64_t max_address;
	uint64_t entry_point;

	int32_t perfIntelPtPerfType = -1;
	cofi_map_t cofi_map;
	uint8_t* code;

	pt_tracer* trace;

public:
	pt_fuzzer(std::string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point);
	void init();
	void start_pt_trace(int pid);
	void stop_pt_trace();
private:
	bool load_binary();
	bool build_cofi_map();
	bool config_pt();

	bool open_pt();

};
bool init_pt_decorder();
bool pt_trace_proc(int pid);
void decode_pt_info();
bool close_pt_trace(int pid);

#endif
