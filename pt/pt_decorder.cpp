#include <iostream>
#include "pt.h"

static int32_t perfIntelPtPerfType = -1;
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

bool init_pt_decorder() {
	uint8_t buf[PATH_MAX + 1];
	ssize_t sz = files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
	if (sz <= 0) {
		std::cerr << "intel processor trace is not supported on this platform." << std::endl;
		exit(-1);
		return false;
	}


	buf[sz] = '\0';
	perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
	return true;
}

struct pt_data_t {
	uint8_t* header_data;
	uint8_t* aux_data;
};

bool perf_create(pt_data_t* pt_data, pid_t pid) {
    //printf("Enabling PERF for PID=%d method=%x\n", pid, method);

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
    pe.type = perfIntelPtPerfType;
    pe.config = (1U << 11); /* Disable RETCompression */

#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    int perf_fd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
		perror("ERROR: ");
        printf("perf_event_open() failed\n");
        return false;
    }

//#if defined(PERF_ATTR_SIZE_VER5)
    pt_data->header_data =
        (uint8_t*)mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (pt_data->header_data == MAP_FAILED) {
		perror("ERROR: ");
		pt_data->header_data = NULL;
        printf(
            "mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl "
            "(up to even 300000000)\n",
            (size_t)_HF_PERF_MAP_SZ + getpagesize());
        close(perf_fd);
        return -1;
    }
	//~ To set up an AUX area, first aux_offset needs to be set with
    //~ an offset greater than data_offset+data_size and aux_size
    //~ needs to be set to the desired buffer size.  The desired off‐
    //~ set and size must be page aligned, and the size must be a
    //~ power of two.
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)pt_data->meta_data;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = _HF_PERF_AUX_SZ;
    pt_data->aux_data =
        (uint8_t*)mmap(NULL, pem->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, pem->aux_offset);
    if (pt_data->aux_data == MAP_FAILED) {
        munmap(pt_data->aux_data, _HF_PERF_MAP_SZ + getpagesize());
        pt_data->aux_data = NULL;
        perror("ERROR: ");
        printf(
            "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to "
            "even 300000000)\n");
        close(perf_fd);
        return -1;
    }
//#else  /* defined(PERF_ATTR_SIZE_VER5) */
    //~ LOG_F("Your <linux_t/perf_event.h> includes are too old to support Intel PT/BTS");
//#endif /* defined(PERF_ATTR_SIZE_VER5) */

    return perf_fd;
}

bool perf_open(pid_t pid, run_t* run) {
	pt_data_t pt_data;
	int perf_fd = perf_create(&pt_data, pid);
	if (perf_fd == -1) {
		printf("Cannot set up perf for PID=%d (_HF_DYNFILE_IPT_BLOCK)\n", pid);
		goto out;
	}

    return true;
out:
    //close(run->linux_t.cpuIptBtsFd);
    //run->linux_t.cpuIptBtsFd = 1;
    return false;
}

void enable_trace(int fd) {
    if(ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0){
		std::cerr << "enable pt trace for fd " << fd  << " failed." << std::endl;
		exit(-1);
	}
}

void disable_trace(int fd) {
	if(ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) < 0) {
		std::cerr << "disable trace for fd " << fd << " failed." << std::endl;
		exit(-1);
	}
}

void start_pt_trace(int pid) {
	if (perf_open(pid, run) == false) {
		std::cerr << "open perf for pid " << pid << " failed." << std::endl;
		exit(-1);
	}

	if (perf_enable(run) == false) {
		std::cerr << "Couldn't enable perf counters for pid " << pid << "." << std::endl;
		exit(-1);
	}
}

bool pt_analyze(run_t* run) {

    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    uint64_t aux_tail = ATOMIC_GET(pem->aux_tail);
    uint64_t aux_head = ATOMIC_GET(pem->aux_head);

    decode_buffer(run->decoder, run->linux_t.perfMmapAux, (aux_head -1 - aux_tail), run);
    //free and reset the tnt cache memory
    run->decoder->tnt_cache_state = pt_decoder_reset(run->decoder);
    if(run->decoder->tnt_cache_state == NULL)
    {
		printf("Free and reset tnt cache failed!\n");
		return false;
	}
    return true;
}

bool perf_mmap_parse(run_t* run) {
//#if defined(PERF_ATTR_SIZE_VER5)
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
    if (pem->aux_head == pem->aux_tail) {
        printf("The aux_head == aux_tail\n");
        //return false;
    }
    if (pem->aux_head < pem->aux_tail) {
        printf("The PERF AUX data has been overwritten. The AUX buffer is too small\n");
        //return false;
    }
    if (_HF_DYNFILE_IPT_BLOCK) {
        if(pt_analyze(run) == false)
			return false;
    }
    return true;
//#endif /* defined(PERF_ATTR_SIZE_VER5) */
}

bool stop_pt_trace_and_decode(run_t* run) {

	disable_trace();

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

	return true;
}

void decode_buffer(decoder_t* self, uint8_t* map, size_t len, run_t* run){
	unsigned char *end = map + len;
	unsigned char *p;
	uint8_t byte0;

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
				append_tnt_cache(tnt_cache_t* self, true, (uint64_t)(&p));
				p ++;
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

bool decode_pt_info() {
	struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
	if (pem->aux_head == pem->aux_tail) {
		printf("The aux_head == aux_tail\n");
		return false;
	}
	if (pem->aux_head < pem->aux_tail) {
		printf("The PERF AUX data has been overwritten. The AUX buffer is too small\n");
		return false;
	}

	struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->linux_t.perfMmapBuf;
	uint64_t aux_tail = ATOMIC_GET(pem->aux_tail);
	uint64_t aux_head = ATOMIC_GET(pem->aux_head);

	decode_buffer(run->decoder, run->linux_t.perfMmapAux, (aux_head -1 - aux_tail), run);
	//free and reset the tnt cache memory
	run->decoder->tnt_cache_state = pt_decoder_reset(run->decoder);
	if(run->decoder->tnt_cache_state == NULL)
	{
		printf("Free and reset tnt cache failed!\n");
		return false;
	}
	return true;
}

bool close_pt_trace(int pid) {

}
