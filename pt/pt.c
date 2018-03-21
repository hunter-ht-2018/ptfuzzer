#include "pt.h"
/////////////////////////////////////////////////////
//~ 1.pt的打开

//~ 针对每个test case，
//~ 1）主进程fork出一个子进程，利用之前记录的命令行以及输入的文件，运行目标程序
//~ 2）主进程利用ptrace attach对子进程进行监控
//~ 3）attach之后开启perf_event，其中perf_event_attr这个结构体是关键，pe.enable_on_exec = 1，pe.type = PERF_TYPE_HARDWARE，
//~ 	函数perf_event_open(&pe, pid,  ...)返回一个文件描述符perfFd，然后ioctl(perfFd, PERF_EVENT_IOC_ENABLE, ...)
//~ 	打开了processor tracing，perf_open()->perf_create()->perf_event_open()->perf_enable()->ioctl()

//~ 4)在配置perf的同时，还利用mmap(..., *perfFd, ...)初始化了一块内存用于记录信息


//~ 2.pt记录信息

//~ 3.pt解析decode_buffer()


/////////////////////////////////////////////////////
//~ processor tracing环境要求

//~ 1.内核>=4.2

//~ 1.Broadwell architecture
/////////////////////////////////////////////////////


/////////////////////////////////////////////////////

//~ tnt指令解析，pci_kafl_guest_realize中的tmp0, tmp1的值

/////////////////////////////////////////////////////


///////////////////////全局变量
static int32_t perfIntelPtPerfType = -1;
uint64_t last_ip = 0ULL;
static uint8_t psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

uint8_t* trace_bits;    

///////////////////////


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

ssize_t files_readFileToBufMax(char* fileName, uint8_t* buf, size_t fileMaxSz) {
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

bool perf_init() {
	//AFL里面有无malloc？
	trace_bits = malloc(MAP_SIZE * sizeof(uint8_t));
	if(trace_bits == NULL)
	{
		return false;
	}
	
    uint8_t buf[PATH_MAX + 1];
    ssize_t sz =
        files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = '\0';
        perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
    }
    else return false;

    return true;
}

bool perf_open(pid_t pid, run_t* run) {

    if (_HF_DYNFILE_IPT_BLOCK) {
        if (perf_create(run, pid, _HF_DYNFILE_IPT_BLOCK, &run->linux_t.cpuIptBtsFd) == false) {
            printf("Cannot set up perf for PID=%d (_HF_DYNFILE_IPT_BLOCK)\n", pid);
            goto out;
        }
    }

    return true;

out:
    close(run->linux_t.cpuIptBtsFd);
    run->linux_t.cpuIptBtsFd = 1;

    return false;
}

void perf_close(run_t* run) {

    if (run->linux_t.perfMmapAux != NULL) {
        munmap(run->linux_t.perfMmapAux, _HF_PERF_AUX_SZ);
        run->linux_t.perfMmapAux = NULL;
    }
    if (run->linux_t.perfMmapBuf != NULL) {
        munmap(run->linux_t.perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        run->linux_t.perfMmapBuf = NULL;
    }

    if (_HF_DYNFILE_IPT_BLOCK) {
        close(run->linux_t.cpuIptBtsFd);
        run->linux_t.cpuIptBtsFd = -1;
    }
}

bool perf_enable(run_t* run) {

    if (_HF_DYNFILE_IPT_BLOCK) {
        if(ioctl(run->linux_t.cpuIptBtsFd, PERF_EVENT_IOC_ENABLE, 0) < 0)
	{
		return false;
	}
    }
    return true;
}

bool perf_create(run_t* run, pid_t pid, dynFileMethod_t method, int* perfFd) {
    //printf("Enabling PERF for PID=%d method=%x\n", pid, method);

    if (*perfFd != -1) {
        printf("The PERF FD is already initialized, possibly conflicting perf types enabled\n");
        exit(1);
    }

    if ((method & _HF_DYNFILE_IPT_BLOCK) && perfIntelPtPerfType == -1) {
        printf("Intel PT events are not supported on this platform\n");
        exit(1);
    }

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
    pe.type = PERF_TYPE_HARDWARE;

    switch (method) {
        case _HF_DYNFILE_IPT_BLOCK:
            //printf("Using: (Intel PT) type=%" PRIu32 " for PID: %d\n", perfIntelPtPerfType, pid);
            pe.type = perfIntelPtPerfType;
            pe.config = (1U << 11); /* Disable RETCompression */
            break;
        default:
            printf("Unknown perf mode: '%d' for PID: %d\n", method, pid);
            return false;
            break;
    }

#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    *perfFd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (*perfFd == -1) {
		perror("ERROR: ");
        printf("perf_event_open() failed\n");
        return false;
    }

    if (method != _HF_DYNFILE_IPT_BLOCK) {
        return true;
    }
#if defined(PERF_ATTR_SIZE_VER5)
    run->linux_t.perfMmapBuf =
        mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0);
    if (run->linux_t.perfMmapBuf == MAP_FAILED) {
		perror("ERROR: ");
        run->linux_t.perfMmapBuf = NULL;
        printf(
            "mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl "
            "(up to even 300000000)\n",
            (size_t)_HF_PERF_MAP_SZ + getpagesize());
        close(*perfFd);
        *perfFd = -1;
        return false;
    }
	//~ To set up an AUX area, first aux_offset needs to be set with
    //~ an offset greater than data_offset+data_size and aux_size
    //~ needs to be set to the desired buffer size.  The desired off‐
    //~ set and size must be page aligned, and the size must be a
    //~ power of two.
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = _HF_PERF_AUX_SZ;
    run->linux_t.perfMmapAux =
        mmap(NULL, pem->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, pem->aux_offset);
    if (run->linux_t.perfMmapAux == MAP_FAILED) {
        munmap(run->linux_t.perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        run->linux_t.perfMmapBuf = NULL;
        perror("ERROR: ");
        printf(
            "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to "
            "even 300000000)\n");
        close(*perfFd);
        *perfFd = -1;
        return false;
    }
#else  /* defined(PERF_ATTR_SIZE_VER5) */
    //~ LOG_F("Your <linux_t/perf_event.h> includes are too old to support Intel PT/BTS");
#endif /* defined(PERF_ATTR_SIZE_VER5) */

    return true;
}

bool perf_config(pid_t pid, run_t* run)
{


	last_ip = 0ULL;
	perf_close(run);
	if (perf_open(pid, run) == false) {
		//////////////////////////////////
		//////pid是运行目标程序的子进程的pid/////////////
		/////////////////////////////////
		return false;
	}

	if (perf_enable(run) == false) {
		perror("ERROR: ");
		printf("Couldn't enable perf counters for pid %d\n", pid);
		return false;
	}
	return true;
}


void pt_bitmap(uint64_t addr)
{	
	//64位地址截断为16位
    uint16_t last_ip16, addr16, pos16;
    last_ip16 = (uint16_t)(last_ip);
    addr16 = (uint16_t)(addr);
    pos16 = (uint16_t)(last_ip16 ^ addr16);
    trace_bits[pos16]++;

    last_ip = addr >> 1;
}

decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t)){
	decoder_t* res = malloc(sizeof(decoder_t));
	res->code = code;
	res->min_addr = min_addr;
	res->max_addr = max_addr;
	res->handler = handler;

	res->last_tip = 0;
	res->last_ip2 = 0;
	res->fup_pkt = false;
	res->isr = false;
	res->in_range = false;
	
	res->disassembler_state = init_disassembler(code, min_addr, max_addr, handler);
    res->tnt_cache_state = tnt_cache_init();
	
	return res;
}

void pt_decoder_destroy(decoder_t* self){
	if(self->tnt_cache_state){
        destroy_disassembler(self->disassembler_state);
        tnt_cache_destroy(self->tnt_cache_state);
        self->tnt_cache_state = NULL;
    }
	free(self);
}

void pt_decoder_flush(decoder_t* self){
	self->last_tip = 0;
	self->last_ip2 = 0;
	self->fup_pkt = false;
	self->isr = false;
	self->in_range = false;
}

uint64_t get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
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

static inline void tsc_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_TSC_LEN;
}

static inline void mtc_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_MTC_LEN;
}


static inline void pad_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p)++;
}

static inline void tnt8_handler(decoder_t* self, uint8_t** p){
	(void)self;
	append_tnt_cache(self->tnt_cache_state, true, (uint64_t)(**p));
	(*p)++;
}

static inline void cbr_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_CBR_LEN;
}

static inline void mode_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_MODE_LEN;
}

static inline void tip_handler(decoder_t* self, uint8_t** p, uint8_t** end, run_t* run){
	if (count_tnt(self->tnt_cache_state)){
		trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
}

static inline void tip_pge_handler(decoder_t* self, uint8_t** p, uint8_t** end, run_t* run){
	self->pge_enabled = true;
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
	trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
}

static inline void tip_pgd_handler(decoder_t* self, uint8_t** p, uint8_t** end, run_t* run){
	self->pge_enabled = false;
	if (count_tnt(self->tnt_cache_state)){
		trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
}

static inline void tip_fup_handler(decoder_t* self, uint8_t** p, uint8_t** end, run_t* run){
	if (count_tnt(self->tnt_cache_state)){
		trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
}

static inline void pip_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_PIP_LEN-6;
}

static inline void psb_handler(decoder_t* self, uint8_t** p){
	(*p) += PT_PKT_PSB_LEN;
	pt_decoder_flush(self);
}

static inline void psbend_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_PSBEND_LEN;
}

static inline void long_tnt_handler(decoder_t* self, uint8_t** p){
	if (self->pge_enabled)
        append_tnt_cache(self->tnt_cache_state, false, (uint64_t)*p);
	(*p) += PT_PKT_LTNT_LEN;
}

static inline void ts_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_TS_LEN;
}

static inline void ovf_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_OVF_LEN;
}

static inline void mnt_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_MNT_LEN;
}

static inline void tma_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_TMA_LEN;
}

static inline void vmcs_handler(decoder_t* self, uint8_t** p){
	(void)self;
	(*p) += PT_PKT_VMCS_LEN;
}

static inline void print_unknown(unsigned char* p, unsigned char* end)
{
	//printf("unknown packet: ");
	unsigned len = end - p;
	int i;
	if (len > 16)
		len = 16;
	for (i = 0; i < len; i++)
	{
		//printf("%02x ", p[i]);
	}
	//printf("\n");
}

void decode_buffer(decoder_t* self, uint8_t* map, size_t len, run_t* run){
	unsigned char *end = map + len;
	unsigned char *p;
	uint8_t byte0;

	for (p = map; p < end; ) {
		p = memmem(p, end - p, psb, PT_PKT_PSB_LEN);
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
				pad_handler(self, &p);
				continue;
			}

			//TSC
			if (*p == PT_PKT_TSC_BYTE0 && LEFT(PT_PKT_TSC_LEN)){
				tsc_handler(self, &p);
				continue;
			}

			//MTC
			if (*p == PT_PKT_MTC_BYTE0 && LEFT(PT_PKT_MTC_LEN)){
				mtc_handler(self, &p);
				continue;
			}

			/* tnt8 */
			if ((byte0 & BIT(0)) == 0 && byte0 != 2){
				tnt8_handler(self, &p);
				continue;
			}

			/* CBR */
			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_CBR_LEN) && p[1] == PT_PKT_CBR_BYTE1) {
				cbr_handler(self, &p);
				continue;
			}

			/* MODE */
			if (byte0 == PT_PKT_MODE_BYTE0 && LEFT(PT_PKT_MODE_LEN)) {
				mode_handler(self, &p);
				continue;
			}

			switch (byte0 & PT_PKT_TIP_MASK) {

				/* tip */
				case PT_PKT_TIP_BYTE0:
				{
					tip_handler(self, &p, &end, run);
					continue;
				}

				/* tip.pge */
				case PT_PKT_TIP_PGE_BYTE0:
				{
					tip_pge_handler(self, &p, &end, run);
					continue;
				}

				/* tip.pgd */
				case PT_PKT_TIP_PGD_BYTE0:
				{
					tip_pgd_handler(self, &p, &end, run);
					continue;
				}

				/* tip.fup */
				case PT_PKT_TIP_FUP_BYTE0:
				{
					tip_fup_handler(self, &p, &end, run);
					continue;
				}
				default:
					break;
			}

			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_GENERIC_LEN)) {

				/* PIP */
				if (p[1] == PT_PKT_PIP_BYTE1 && LEFT(PT_PKT_PIP_LEN)) {
					pip_handler(self, &p);
					continue;
				}

				/* PSB */
				if (p[1] == PT_PKT_PSB_BYTE1 && LEFT(PT_PKT_PSB_LEN) && !memcmp(p, psb, PT_PKT_PSB_LEN)) {
					psb_handler(self, &p);
					continue;
				}

				/* PSBEND */
				if (p[1] == PT_PKT_PSBEND_BYTE1) {
					psbend_handler(self, &p);
					continue;
				}

				/* long TNT */
				if (p[1] == PT_PKT_LTNT_BYTE1 && LEFT(PT_PKT_LTNT_LEN)) {
					long_tnt_handler(self, &p);
					continue;
				}

				/* TS */
				if (p[1] == PT_PKT_TS_BYTE1) {
					ts_handler(self, &p);
					continue;
				}

				/* OVF */
				if (p[1] == PT_PKT_OVF_BYTE1 && LEFT(PT_PKT_OVF_LEN)) {
					ovf_handler(self, &p);
					continue;
				}

				/* MNT */
				if (p[1] == PT_PKT_MNT_BYTE1 && LEFT(PT_PKT_MNT_LEN) && p[2] == PT_PKT_MNT_BYTE2) {
					mnt_handler(self, &p);
					continue;
				}

				/* TMA */
				if (p[1] == PT_PKT_TMA_BYTE1 && LEFT(PT_PKT_TMA_LEN)) {
					tma_handler(self, &p);
					continue;
				}

				/* VMCS */
				if (p[1] == PT_PKT_VMCS_BYTE1 && LEFT(PT_PKT_VMCS_LEN)) {
					vmcs_handler(self, &p);
					continue;
				}
			}

			print_unknown(p, end);
			return;
		}
	}
}

#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)

bool pt_decoder_reset(decoder_t* self)
{
	self->last_tip = 0;
	self->last_ip2 = 0;
	self->fup_pkt = false;
	self->isr = false;
	self->in_range = false;
	
	if(reset_disassembler(self->disassembler_state) == false)
	{
		printf("Reset disassembler failed!\n");
		return false;
	}
    if(tnt_cache_reset(self->tnt_cache_state) == false)
    {
		printf("Reset tnt cache failed!\n");
		return false;
	}
    
    return true;
}

bool pt_analyze(run_t* run) {

    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    uint64_t aux_tail = ATOMIC_GET(pem->aux_tail);
    uint64_t aux_head = ATOMIC_GET(pem->aux_head);

	if(pt_decoder_reset(run->decoder) == false)
	{
		printf("PT decoder reset failed!\n");
		return false;
	}
    decode_buffer(run->decoder, run->linux_t.perfMmapAux, (aux_head -1 - aux_tail), run);
    free_list(run->decoder->disassembler_state->list_head);
    return true;
}

#define wmb() __sync_synchronize()
bool perf_mmap_reset(run_t* run) {
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    ATOMIC_SET(pem->data_head, 0);
    ATOMIC_SET(pem->data_tail, 0);
#if defined(PERF_ATTR_SIZE_VER5)
    ATOMIC_SET(pem->aux_head, 0);
    ATOMIC_SET(pem->aux_tail, 0);
#endif /* defined(PERF_ATTR_SIZE_VER5) */
    wmb();
    return true;
}

bool perf_mmap_parse(run_t* run) {
#if defined(PERF_ATTR_SIZE_VER5)
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    if (pem->aux_head == pem->aux_tail) {
        printf("The aux_head == aux_tail\n");
        return false;
    }
    if (pem->aux_head < pem->aux_tail) {
        printf("The PERF AUX data has been overwritten. The AUX buffer is too small\n");
        return false;
    }
    if (_HF_DYNFILE_IPT_BLOCK) {
        if(pt_analyze(run) == false)
			return false;
    }
    return true;
#endif /* defined(PERF_ATTR_SIZE_VER5) */
}

bool perf_analyze(run_t* run)
{
	if (_HF_DYNFILE_IPT_BLOCK) {
        if(ioctl(run->linux_t.cpuIptBtsFd, PERF_EVENT_IOC_DISABLE, 0) < 0)
        {
			perror("Error: ");
			return false;
		}
        
        //解析pt之前设置bitmap
        memset(trace_bits, 0, MAP_SIZE);
        
        if(perf_mmap_parse(run) == false)
			return false;
        if(perf_mmap_reset(run) == false)
			return false;
        if(ioctl(run->linux_t.cpuIptBtsFd, PERF_EVENT_IOC_RESET, 0) > 0)
        {
			perror("Error: ");
			return false;
		}
    }
    return true;
}

bool perf_reap(run_t* run)
{
	if(perf_analyze(run) == false)
		return false;
	return true;
}

void print_bitmap()
{
	for(int i = 0; i < MAP_SIZE; i++)
		printf("%u", trace_bits[i]);
	printf("\n\n");
}

uint8_t* get_trace_bits()
{
	return trace_bits;
}
