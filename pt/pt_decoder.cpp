#include <iostream>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "pt.h"

#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)
static uint8_t psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

static long perf_event_open(
    struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
        return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu,
                (uintptr_t)group_fd, (uintptr_t)flags);
}

ssize_t files_readFromFd(int fd, uint8_t* buf, size_t fileSz) {
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
        if (sz < 0 && errno == EINTR) continue;

        if (sz == 0) break;

        if (sz < 0) return -1;

        readSz += sz;
    }
    return (ssize_t)readSz;
}

static ssize_t files_readFileToBufMax(char* fileName, uint8_t* buf, size_t fileMaxSz) {
    int fd = open(fileName, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
		perror("ERROR: ");
        printf("Couldn't open '%s' for R/O\n", fileName);
        return -1;
    }

    ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
    if (readSz < 0) {
		perror("ERROR: ");
        printf("Couldn't read '%s' to a buf\n", fileName);
    }
    close(fd);

    //printf("Read '%zu' bytes from '%s'\n", readSz, fileName);
    return readSz;
}

pt_fuzzer::pt_fuzzer(std::string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point) :
	raw_binary_file(raw_binary_file), base_address(base_address), max_address(max_address), entry_point(entry_point),
	code(nullptr) , trace(nullptr){

}

bool pt_fuzzer::config_pt() {
	uint8_t buf[PATH_MAX + 1];
	ssize_t sz = files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
	if (sz <= 0) {
		std::cerr << "intel processor trace is not supported on this platform." << std::endl;
		//exit(-1);
		return false;
	}


	buf[sz] = '\0';
	perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
    std::cout << "config PT OK, perfIntelPtPerfType = " << perfIntelPtPerfType << std::endl;
	return true;
}

bool pt_fuzzer::load_binary() {
    FILE* pt_file = fopen(this->raw_binary_file.c_str(), "rb");
    uint64_t code_size = this->max_address - this->base_address;
    this->code = (uint8_t*)malloc(code_size);
    memset(this->code, 0, code_size);

    if(NULL == pt_file) {
        return false;
    }

    int count = fread (code, code_size, 1, pt_file);
    fclose(pt_file);
    if(count != 1) {
    	return false;
    }
    return true;
}

bool pt_fuzzer::build_cofi_map() {
	uint32_t num_inst = disassemble_binary( this->code, this->base_address, this->max_address, this->cofi_map);
	std::cout << "total number of cofi instructions: " << num_inst << std::endl;
	return true;
}

void pt_fuzzer::init() {
	if(!config_pt()) {
        std::cerr << "config PT failed." << std::endl;
		exit(-1);
	}
    std::cout << "config PT OK." << std::endl;

	if(!load_binary()) {
		std::cerr << "load raw binary file failed." << std::endl;
		exit(-1);
	}
    std::cout << "load binary OK." << std::endl;

	if(!build_cofi_map()){
		std::cerr << "build cofi map for binary failed." << std::endl;
		exit(-1);
	}
    std::cout << "build cofi map OK." << std::endl;
}

void pt_fuzzer::start_pt_trace(int pid) {
	this->trace = new pt_tracer(pid);
	if(!trace->open_pt(perfIntelPtPerfType)){
		std::cerr << "open PT event failed." << std::endl;
		exit(-1);
	}
    std::cout << "open PT event OK." << std::endl;

	if(!trace->start_trace()){
		std::cerr << "start PT event failed." << std::endl;
		exit(-1);
	}
    std::cout << "start to trace process, pid = " << pid << std::endl;
}

void pt_fuzzer::stop_pt_trace() {
	if(!trace->stop_trace()){
		std::cerr << "stop PT event failed." << std::endl;
		exit(-1);
	}
	std::cout << "stop pt trace OK." << std::endl;
	pt_packet_decoder decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this->cofi_map, this->base_address, this->max_address);
	decoder.decode();

	delete this->trace;
	this->trace = nullptr;
}

bool pt_tracer::open_pt(int pt_perf_type) {

	int pid = this->trace_pid;
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    ///////////////
    //不支持kernel-only coverage
    ///////////////
    pe.exclude_kernel = 1;

    ///////////////
    //默认关闭，下一个exec()打开
    ///////////////
    pe.disabled = 1;
    pe.enable_on_exec = 1;
    //pe.type = PERF_TYPE_HARDWARE;
    pe.type = pt_perf_type;
    std::cout << "pe.type = " << pe.type << std::endl;
    pe.config = (1U << 11); /* Disable RETCompression */

#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    perf_fd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        printf("perf_event_open() failed\n");
        return false;
    }

//#if defined(PERF_ATTR_SIZE_VER5)
    this->perf_pt_header =
        (uint8_t*)mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (this->perf_pt_header == MAP_FAILED) {
		perror("ERROR: ");
		this->perf_pt_header = nullptr;
        printf(
            "mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl "
            "(up to even 300000000)\n",
            (size_t)_HF_PERF_MAP_SZ + getpagesize());
        close(perf_fd);
        return false;
    }
	//~ To set up an AUX area, first aux_offset needs to be set with
    //~ an offset greater than data_offset+data_size and aux_size
    //~ needs to be set to the desired buffer size.  The desired off‐
    //~ set and size must be page aligned, and the size must be a
    //~ power of two.
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)this->perf_pt_header;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = _HF_PERF_AUX_SZ;
    this->perf_pt_aux =
        (uint8_t*)mmap(NULL, pem->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, pem->aux_offset);
    if (this->perf_pt_aux == MAP_FAILED) {
        munmap(this->perf_pt_aux, _HF_PERF_MAP_SZ + getpagesize());
        this->perf_pt_aux = NULL;
        perror("ERROR: ");
        printf(
            "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to "
            "even 300000000)\n");
        close(perf_fd);
        return false;
    }
//#else  /* defined(PERF_ATTR_SIZE_VER5) */
    //~ LOG_F("Your <linux_t/perf_event.h> includes are too old to support Intel PT/BTS");
//#endif /* defined(PERF_ATTR_SIZE_VER5) */

    return true;
}

pt_tracer::pt_tracer(int pid) : trace_pid(pid), perf_pt_header(nullptr), perf_pt_aux(nullptr) {

}

bool pt_tracer::start_trace() {
	if(ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0){
		std::cerr << "enable pt trace for fd " << perf_fd  << " failed." << std::endl;
		return false;
	}
	return true;
}

bool pt_tracer::stop_trace(){
	if(ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) < 0) {
		std::cerr << "disable trace for fd " << perf_fd << " failed." << std::endl;
		return false;
	}
	if(ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0) > 0){
		perror("Error: ");
		return false;
	}
	return true;
}


pt_packet_decoder::pt_packet_decoder(uint8_t* perf_pt_header, uint8_t* perf_pt_aux, cofi_map_t& map,
		uint64_t min_address, uint64_t max_address) :
		pt_packets(perf_pt_aux), cofi_map(map), min_address(min_address), max_address(max_address){
	struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)perf_pt_header;
	aux_tail = ATOMIC_GET(pem->aux_tail);
	aux_head = ATOMIC_GET(pem->aux_head);
	trace_bits = (uint8_t*)malloc(MAP_SIZE * sizeof(uint8_t));
    tnt_cache_state = tnt_cache_init();
}

pt_packet_decoder::~pt_packet_decoder() {
	if(trace_bits != nullptr) {
		free(trace_bits);
	}
    if(tnt_cache_state != nullptr){
        tnt_cache_destroy(tnt_cache_state);
    }
}

uint32_t pt_packet_decoder::decode_tnt(uint64_t entry_point){
	uint8_t tnt;
	uint32_t num_tnt_decoded = 0;
	cofi_inst_t* cofi_obj = this->cofi_map[entry_point];
    if(cofi_obj == nullptr){
        std::cerr << "can not find cofi for addr: " << entry_point << std::endl;
        exit(-1);
    }
	while(count_tnt(tnt_cache_state)) {

		tnt = process_tnt_cache(tnt_cache_state);
		switch(tnt){
		case TNT_EMPTY:
			return num_tnt_decoded;
		case TAKEN:
        {
			//~ sample_decoded_detailed("(%d)\t%lx\t(Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH, obj->cofi->ins_addr);
			//self->handler(obj->cofi->ins_addr);
            uint64_t target_addr = cofi_obj->target_addr;
			if (out_of_bounds(target_addr))
				return num_tnt_decoded;
			cofi_obj = cofi_map[target_addr];
            if(cofi_obj == nullptr){
                std::cerr << "can not find cofi for addr: " << target_addr << std::endl;
                exit(-1);
            }
			break;
        }
		case NOT_TAKEN:
			//~ sample_decoded_detailed("(%d)\t%lx\t(Not Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH ,obj->cofi->ins_addr);
			alter_bitmap(cofi_obj->next_cofi->inst_addr);
			cofi_obj = cofi_obj->next_cofi;

			break;
		}
		num_tnt_decoded ++;
	}
	return num_tnt_decoded;
}

uint64_t pt_packet_decoder::get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
{
	unsigned char *p = *pp;
	uint64_t v = *last_ip;
	int i;
	unsigned shift = 0;

	if (len == 0) {
		return 0; /* out of context */
	}
	if (len < 4) {
		if (!LEFT(len)) {
			*last_ip = 0;
			return 0; /* XXX error */
		}
		for (i = 0; i < len; i++, shift += 16, p += 2) {
			uint64_t b = *(uint16_t *)p;
			v = (v & ~(0xffffULL << shift)) | (b << shift);
		}
		v = ((int64_t)(v << (64 - 48))) >> (64 - 48); /* sign extension */
	} else {
		return 0; /* XXX error */
	}

	*pp = p;

	*last_ip = v;
	return v;
}





static inline void print_unknown(unsigned char* p, unsigned char* end)
{
	printf("unknown packet: ");
	unsigned len = end - p;
	int i;
	if (len > 16)
		len = 16;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", p[i]);
	}
	printf("\n");
}
void pt_packet_decoder::decode() {

	if(this->aux_tail >= this->aux_head) {
		std::cerr << "failed to decode: invalid trace data: aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << std::endl;
		return;
	}
	uint8_t* map = this->pt_packets;
	uint64_t len = this->aux_head - this->aux_tail - 1;
	uint8_t* end = map + len;
	unsigned char *p;
	uint8_t byte0;

	std::cout << "try to decode packet buffer: " << (uint64_t)this->pt_packets << ", aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << ", size = " << (int64_t)len << std::endl;
	for (p = map; p < end; ) {
		p = (unsigned char *)memmem(p, end - p, psb, PT_PKT_PSB_LEN);
		if (!p) {
			p = end;
			break;
		}

		int cnt = 0;
		while (p < end) {
			cnt +=1;
			byte0 = *p;

			/* pad */
			if (byte0 == 0) {
				//pad_handler(self, &p);
				p ++;
				continue;
			}

			//TSC
			if (*p == PT_PKT_TSC_BYTE0 && LEFT(PT_PKT_TSC_LEN)){
				//tsc_handler(self, &p);
				p += PT_PKT_TSC_LEN;
				continue;
			}

			//MTC
			if (*p == PT_PKT_MTC_BYTE0 && LEFT(PT_PKT_MTC_LEN)){
				//mtc_handler(self, &p);
				p += PT_PKT_MTC_LEN;
				continue;
			}

			/* tnt8 */
			if ((byte0 & BIT(0)) == 0 && byte0 != 2){
				//tnt8_handler(self, &p);
				append_tnt_cache(this->tnt_cache_state, true, (uint64_t)(&p));
				p ++;
				continue;
			}

			/* CBR */
			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_CBR_LEN) && p[1] == PT_PKT_CBR_BYTE1) {
				//cbr_handler(self, &p);
				p += PT_PKT_CBR_LEN;
				continue;
			}

			/* MODE */
			if (byte0 == PT_PKT_MODE_BYTE0 && LEFT(PT_PKT_MODE_LEN)) {
				//mode_handler(self, &p);
				p += PT_PKT_MODE_LEN;
				continue;
			}

			switch (byte0 & PT_PKT_TIP_MASK) {

				/* tip */
				case PT_PKT_TIP_BYTE0:
				{
					tip_handler(&p, &end);
					continue;
				}

				/* tip.pge */
				case PT_PKT_TIP_PGE_BYTE0:
				{
					tip_pge_handler(&p, &end);
					continue;
				}

				/* tip.pgd */
				case PT_PKT_TIP_PGD_BYTE0:
				{
					tip_pgd_handler( &p, &end);
					continue;
				}

				/* tip.fup */
				case PT_PKT_TIP_FUP_BYTE0:
				{
					tip_fup_handler( &p, &end);
					continue;
				}
				default:
					break;
			}

			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_GENERIC_LEN)) {

				/* PIP */
				if (p[1] == PT_PKT_PIP_BYTE1 && LEFT(PT_PKT_PIP_LEN)) {
					//pip_handler(self, &p);
					p += PT_PKT_PIP_LEN-6;
					continue;
				}

				/* PSB */
				if (p[1] == PT_PKT_PSB_BYTE1 && LEFT(PT_PKT_PSB_LEN) && !memcmp(p, psb, PT_PKT_PSB_LEN)) {
					psb_handler(&p);
					continue;
				}

				/* PSBEND */
				if (p[1] == PT_PKT_PSBEND_BYTE1) {
					//psbend_handler(self, &p);
					p += PT_PKT_PSBEND_LEN;
					continue;
				}

				/* long TNT */
				if (p[1] == PT_PKT_LTNT_BYTE1 && LEFT(PT_PKT_LTNT_LEN)) {
					long_tnt_handler(&p);
					continue;
				}

				/* TS */
				if (p[1] == PT_PKT_TS_BYTE1) {
					//ts_handler(self, &p);
					p += PT_PKT_TS_LEN;
					continue;
				}

				/* OVF */
				if (p[1] == PT_PKT_OVF_BYTE1 && LEFT(PT_PKT_OVF_LEN)) {
					//ovf_handler(self, &p);
					p += PT_PKT_OVF_LEN;
					continue;
				}

				/* MNT */
				if (p[1] == PT_PKT_MNT_BYTE1 && LEFT(PT_PKT_MNT_LEN) && p[2] == PT_PKT_MNT_BYTE2) {
					//mnt_handler(self, &p);
					p += PT_PKT_MNT_LEN;
					continue;
				}

				/* TMA */
				if (p[1] == PT_PKT_TMA_BYTE1 && LEFT(PT_PKT_TMA_LEN)) {
					//tma_handler(self, &p);
					p += PT_PKT_TMA_LEN;
					continue;
				}

				/* VMCS */
				if (p[1] == PT_PKT_VMCS_BYTE1 && LEFT(PT_PKT_VMCS_LEN)) {
					//vmcs_handler(self, &p);
					p += PT_PKT_VMCS_LEN;
					continue;
				}
			}

			print_unknown(p, end);
			return;
		}
	}
}

void pt_packet_decoder::flush(){
	this->last_tip = 0;
	this->last_ip2 = 0;
	this->fup_pkt = false;
	this->isr = false;
	this->in_range = false;
}

