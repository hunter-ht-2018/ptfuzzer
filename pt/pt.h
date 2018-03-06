

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

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 8192
#define _HF_PERF_MAP_SZ (1024 * 512)
#define _HF_PERF_AUX_SZ (1024 * 1024)
#define _HF_PERF_BITMAP_SIZE_16M (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7ffffff

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
    }linux;
}run_t;

typedef enum {
    _HF_DYNFILE_NONE = 0x0,
    _HF_DYNFILE_INSTR_COUNT = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_BTS_EDGE = 0x10,
    _HF_DYNFILE_IPT_BLOCK = 0x20,
    _HF_DYNFILE_SOFT = 0x40,
}dynFileMethod_t;

typedef struct decoder_s{
	uint64_t min_addr;
	uint64_t max_addr;
	void (*handler)(uint64_t, run_t*);
	uint64_t last_tip;
	uint64_t last_ip2;
	bool fup_pkt;
	bool isr;
	bool in_range;
	bool pge_enabled;
} decoder_t;


void perf_config(pid_t pid, run_t* run);
bool perf_init();
bool perf_open(pid_t pid, run_t* run);
void perf_close(run_t* run);
bool perf_enable(run_t* run);
void perf_analyze(run_t* run);
bool perf_create(run_t* run, pid_t pid, dynFileMethod_t method, int* perfFd);
void perf_reap(run_t* run);
void perf_mmap_parse(run_t* run);
void perf_mmap_reset(run_t* run);
void pt_bitmap(uint64_t addr, run_t* run);
void pt_analyze(run_t* run);
decoder_t* pt_decoder_init(uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t, run_t*));
void decode_buffer(decoder_t* self, uint8_t* map, size_t len, run_t* run);
void pt_decoder_destroy(decoder_t* self);
void pt_decoder_flush(decoder_t* self);
void pt_bitmap(uint64_t addr, run_t* run);

#endif
