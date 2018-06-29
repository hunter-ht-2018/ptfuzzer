#include <iostream>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <assert.h>
#include <vector>
#include <sstream>
#include <map>
#include "pt.h"
#include "utils.h"

#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)
bool perf_support_ip_filter = true; //assume platform support ip filter in perf
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


void load_config_file(std::map<std::string, std::string>& config_kvs) {
    char line_buf[4096];
    FILE* f = fopen("ptfuzzer.conf", "r");
    if(f == nullptr) {
        f = fopen("/etc/ptfuzzer.conf", "r");
    }
    if(f == nullptr) {
        return;
    }
    while(fgets(line_buf, 4096, f) != nullptr) {
        std::string line(line_buf);
        //trim(line);
        //if(line[0] == '#') continue;
        size_t pos = line.find("#");
        if(pos != std::string::npos) {
            line = line.substr(0, pos);
        }
        trim(line);
        if(line.size() == 0) continue;
        std::istringstream is_line(line);
        std::string key;
        if( std::getline(is_line, key, '=') ) {
            std::string value;
            if( std::getline(is_line, value) )
                config_kvs[key] = value;
        }
    }

    fclose(f);

}

void fuzzer_config::load_config() {
    std::map<std::string, std::string> config_kvs;
    load_config_file(config_kvs);

    std::string branch_mode = config_kvs["BRANCH_MODE"];
    if(branch_mode != "") {
        if(branch_mode == "TIP_MODE") {
            this->branch_mode = TIP_MODE;
        }
        else if(branch_mode == "TNT_MODE") {
            this->branch_mode = TNT_MODE;
        }
        else if(branch_mode == "FAKE_TNT_MODE") {
            this->branch_mode = FAKE_TNT_MODE;
        }
        else {
            std::cerr << "config BRANCH_MODE(" << branch_mode << ") env error, ignore it." << std::endl;
        }
    }
    else {
        std::cerr << "BRANCH_MODE is null, using default TNT mode." << std::endl;
    }
    switch(this->branch_mode) {
    case TIP_MODE:
        std::cout << "Run ptfuzzer with TIP_MODE" << std::endl;
        break;
    case TNT_MODE:
        std::cout << "Run ptfuzzer with TNT_MODE" << std::endl;
        break;
    case FAKE_TNT_MODE:
        std::cout << "Run ptfuzzer with FAKE_TNT_MODE." << std::endl;
        break;
    default:
        std::cerr << "unkown branch mode." << std::endl;
        assert(false);
    }

    // load aux buffer size
    std::string config_aux_buffer_size = config_kvs["PERF_AUX_BUFFER_SIZE"];
    if(config_aux_buffer_size != "") {
        uint64_t msize = std::stoul(config_aux_buffer_size, nullptr, 0);
        this->perf_aux_size = msize * 1024 * 1024;
        std::cout << "Using perf AUX buffer size: " << msize << " MB." << std::endl;
    }
}

fuzzer_config& get_fuzzer_config() {
    static fuzzer_config config;
    return config;
}

pt_fuzzer::pt_fuzzer(std::string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point) :
	        raw_binary_file(raw_binary_file), base_address(base_address), max_address(max_address), entry_point(entry_point),
	        code(nullptr) , trace(nullptr), cofi_map(base_address, max_address-base_address) {
#ifdef DEBUG
    std::cout << "init pt fuzzer: raw_binary_file = " << raw_binary_file << ", min_address = " << base_address
            << ", max_address = " << max_address << ", entry_point = " << entry_point << std::endl;
#endif

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
#ifdef DEBUG
    std::cout << "config PT OK, perfIntelPtPerfType = " << perfIntelPtPerfType << std::endl;
#endif

#ifdef DEBUG
    std::cout << "try to write msr for ip filter." << std::endl;
#endif
    char ip_low[64];
    char ip_high[64];
    sprintf(ip_low, "%ld", this->base_address);
    sprintf(ip_high, "%ld", this->max_address);
    char* reg_value[2] = {ip_low, NULL};
    wrmsr_on_all_cpus(0x580, 1, reg_value); //set low limit for ip filtering
    reg_value[0] = ip_high;
    wrmsr_on_all_cpus(0x581, 1, reg_value); //set high limit for ip filtering
#ifdef DEBUG
    rdmsr_on_all_cpus(0x580);
    rdmsr_on_all_cpus(0x581);
    std::cout << "after wrmsr" << std::endl;
#endif

    return true;
}

bool pt_fuzzer::load_binary() {
    FILE* pt_file = fopen(this->raw_binary_file.c_str(), "rb");
    if(pt_file == nullptr) {
        return false;
    }
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
    std::cout << "start to disassmble binary..." << std::endl;
    uint64_t total_code_size = this->max_address - this->base_address;
    uint64_t code_size = total_code_size;
    uint32_t num_inst = disassemble_binary( this->code, this->base_address, code_size, this->cofi_map);
    cofi_map.set_decode_info(base_address, total_code_size - code_size);
    std::cout << "build_cofi_map, total number of cofi instructions: " << num_inst << std::endl;
    std::cout << "cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << std::endl;
    //std::cout << "first addr = " << cofi_map.begin()->first << std::endl;
    //std::cout << "last addr = " << (cofi_map.rbegin())->first << std::endl;
    return true;
}

bool pt_fuzzer::fix_cofi_map(uint64_t tip) {
    assert(tip >= this->base_address);
    uint64_t offset = tip - this->base_address;
    uint64_t total_code_size = this->max_address - tip;
    uint64_t code_size = total_code_size;
    uint32_t num_inst = disassemble_binary( this->code + offset, tip, code_size, this->cofi_map);
    cofi_map.set_decode_info(tip, total_code_size - code_size);
    std::cout << "fix_cofi_map: decode " << num_inst << " number of instructions." << std::endl;
    std::cout << "cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << std::endl;
    return true;
}

void pt_fuzzer::init() {
    if(!config_pt()) {
        std::cerr << "config PT failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "config PT OK." << std::endl;
#endif

    if(!load_binary()) {
        std::cerr << "load raw binary file failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "load binary OK." << std::endl;
#endif

    if(!build_cofi_map()){
        std::cerr << "build cofi map for binary failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "build cofi map OK." << std::endl;
#endif

}

void pt_fuzzer::start_pt_trace(int pid) {
    this->trace = new pt_tracer(pid);
    if(!trace->open_pt(perfIntelPtPerfType)){
        std::cerr << "open PT event failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "open PT event OK." << std::endl;
#endif

    // if(!trace->start_trace()){
    // 	std::cerr << "start PT event failed." << std::endl;
    // 	exit(-1);
    // }
#ifdef DEBUG
    std::cout << "after start_trace" << std::endl;
#endif
    //rdmsr_on_all_cpus(0x570);

#ifdef DEBUG
    std::cout << "start to trace process, pid = " << pid << std::endl;
#endif
}

void pt_fuzzer::stop_pt_trace(uint8_t *trace_bits) {
    if(!this->trace->stop_trace()){
        std::cerr << "stop PT event failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "stop pt trace OK." << std::endl;
#endif
    pt_packet_decoder decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this);
    decoder.decode(get_fuzzer_config().branch_mode);
#ifdef DEBUG
    std::cout << "decode finished, total number of decoded branch: " << decoder.num_decoded_branch << std::endl;
#endif
    this->trace->close_pt();
    delete this->trace;
    this->trace = nullptr;
    memcpy(trace_bits, decoder.get_trace_bits(), MAP_SIZE);
    num_runs ++;
}

pt_packet_decoder* pt_fuzzer::debug_stop_pt_trace(uint8_t *trace_bits, branch_info_mode_t mode) {
    if(!this->trace->stop_trace()){
        std::cerr << "stop PT event failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "stop pt trace OK." << std::endl;
#endif
    pt_packet_decoder* decoder = new pt_packet_decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this);
    decoder->set_tracing_flag();
    decoder->decode(mode);
#ifdef DEBUG
    std::cout << "decode finished, total number of decoded branch: " << decoder->num_decoded_branch << std::endl;
#endif
    this->trace->close_pt();
    delete this->trace;
    this->trace = nullptr;
    memcpy(trace_bits, decoder->get_trace_bits(), MAP_SIZE);
    num_runs ++;
    return decoder;
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
#ifdef DEBUG
    std::cout << "pe.type = " << pe.type << std::endl;
#endif
    pe.config = (1U << 11); /* Disable RETCompression */
#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    perf_fd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        printf("perf_event_open() failed\n");
        return false;
    }
    if(perf_support_ip_filter) {
        if(ioctl(perf_fd, PERF_EVENT_IOC_SET_FILTER, "filter 0x580/580@/bin/bash") < 0){
            std::cerr << "Warning: set filter for fd " << perf_fd  << " failed, hardware ip filter may not supported." << std::endl;
            std::cerr << "We stop trying to set ip filter again." << std::endl;
            perf_support_ip_filter = false;
        }
    }

#ifdef DEBUG
    std::cout << "before wrmsr" << std::endl;
#endif
    //char* reg_value[2] = {"0x100002908", nullptr};
    //rdmsr_on_all_cpus(0x570);
    //wrmsr_on_all_cpus(0x570, 1, reg_value);
#ifdef DEBUG
    std::cout << "after wrmsr" << std::endl;
#endif
    //rdmsr_on_all_cpus(0x570);
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
    pem->aux_size = get_fuzzer_config().perf_aux_size;
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

#ifdef DEBUG
    std::cout << "after mmap" << std::endl;
#endif
    //rdmsr_on_all_cpus(0x570);
    return true;
}

void pt_tracer::close_pt() {
    munmap(this->perf_pt_aux, get_fuzzer_config().perf_aux_size);
    this->perf_pt_aux = NULL;
    munmap(this->perf_pt_header, _HF_PERF_MAP_SZ + getpagesize());
    this->perf_pt_header = NULL;
    close(perf_fd);
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


pt_packet_decoder::pt_packet_decoder(uint8_t* perf_pt_header, uint8_t* perf_pt_aux, pt_fuzzer* fuzzer) :
                        pt_packets(perf_pt_aux),
                        fuzzer(fuzzer),
                        cofi_map(fuzzer->get_cofi_map()),
                        min_address(fuzzer->get_base_address()),
                        max_address(fuzzer->get_max_address()),
                        app_entry_point(fuzzer->get_entry_point()) {
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)perf_pt_header;
    aux_tail = ATOMIC_GET(pem->aux_tail);
    aux_head = ATOMIC_GET(pem->aux_head);
    trace_bits = (uint8_t*)malloc(MAP_SIZE * sizeof(uint8_t));
    memset(trace_bits, 0, MAP_SIZE);
    tnt_cache_state = tnt_cache_init();
#ifdef DEBUG
    std::cout << "app_entry_point = " << app_entry_point << std::endl;
#endif
}

pt_packet_decoder::~pt_packet_decoder() {
    if(trace_bits != nullptr) {
        free(trace_bits);
    }
    if(tnt_cache_state != nullptr){
        tnt_cache_destroy(tnt_cache_state);
    }
}

void pt_packet_decoder::print_tnt(tnt_cache_t* tnt_cache){
    uint32_t count = count_tnt(tnt_cache);
#ifdef DEBUG
    std::cout << " " << count << " ";
#endif
    uint8_t tnt;
    for(int i = 0; i < count; i ++) {
        tnt = process_tnt_cache(tnt_cache);
        switch(tnt){
        case TAKEN:
#ifdef DEBUG
            std::cout << "T";
#endif
            break;
        case NOT_TAKEN:
#ifdef DEBUG
            std::cout << "N";
#endif
            break;
        default:
            break;
        }
    }
#ifdef DEBUG
    std::cout << std::endl;
#endif
}

cofi_inst_t* pt_packet_decoder::get_cofi_obj(uint64_t addr) {
    cofi_inst_t* cofi_obj = cofi_map.get(addr);
    if(cofi_obj == nullptr){
#ifdef DEBUG
        std::cout << "can not find cofi for addr: " << std::hex << "0x" << addr << std::endl;
#endif
        if(addr == 0) return nullptr;
        else if(out_of_bounds(addr)) {
#ifdef DEBUG
            std::cout << std::hex << "addr " << addr << " out of bounds(" << this->min_address << ", " << this->max_address << ")." << std::endl;
#endif
            return nullptr;
        }
        fuzzer->fix_cofi_map(addr);
        cofi_obj = cofi_map.get(addr);
        assert(cofi_obj != nullptr);
    }
    return cofi_obj;
}

void pt_packet_decoder::decode_tip(uint64_t tip) {
    if(out_of_bounds(tip)) return;
    if(this->branch_info_mode == TNT_MODE) {    // accurate TNT decoding.
        assert(tip !=0);
        cofi_inst_t* cofi_obj = get_cofi_obj(tip);
        alter_bitmap(cofi_obj->inst_addr);
    }
    else {   //TIP_MODE or FAKE_TNT_MODE
        alter_bitmap(tip);
    }
}

uint32_t pt_packet_decoder::decode_tnt(uint64_t entry_point){
    uint8_t tnt;
    uint32_t num_tnt_decoded = 0;
    cofi_inst_t* cofi_obj = nullptr;
#ifdef DEBUG
    std::cout << "call in decode_tnt" << std::endl;
#endif

    if(!start_decode){
#ifdef DEBUG
        std::cout << "not start_decode, return." << std::endl;
#endif
        return 0;
    }

#ifdef DEBUG
    std::cout << "calling decode_tnt for entry_point: " << std::hex << entry_point << std::endl;
#endif
    if(entry_point == 0) return 0;
    cofi_obj = this->get_cofi_obj(entry_point);
    if(cofi_obj == nullptr){
#ifdef DEBUG
        std::cerr << "can not find cofi for entry_point: " << std::hex << "0x" << entry_point << std::endl;
        std::cerr << "number of decoded branches: " << num_decoded_branch << std::endl;
#endif
        return 0;
    }

#ifdef DEBUG
    std::cout << "decode_tnt: before while, start_decode = " << this->start_decode << std::endl; 
#endif
    while(cofi_obj != nullptr) {
        //alter_bitmap(cofi_obj->inst_addr);
        switch(cofi_obj->type){

        case COFI_TYPE_CONDITIONAL_BRANCH:
            tnt = process_tnt_cache(tnt_cache_state);

#ifdef DEBUG
            std::cout << "decode tnt: "  << std::endl;
#endif
            switch(tnt){
            case TNT_EMPTY:
#ifdef DEBUG
                std::cerr << "warning: case TNT_EMPTY." << std::endl;
#endif
                return num_tnt_decoded;
            case TAKEN:
            {
#ifdef DEBUG
                std::cout << "inst " << cofi_obj->inst_addr << " TAKEN, target = " << cofi_obj->target_addr << std::endl;
#endif
                uint64_t target_addr = cofi_obj->target_addr;
                //if (out_of_bounds(target_addr)){
                //    std::cerr << "error: tnt target out of bounds, inst address = " << std::hex << cofi_obj->inst_addr << ", target = " << target_addr << std::endl;
                //	return num_tnt_decoded;
                //}
                assert(target_addr != 0);
                cofi_obj = get_cofi_obj(target_addr);
                break;
            }
            case NOT_TAKEN:
                //~ sample_decoded_detailed("(%d)\t%lx\t(Not Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH ,obj->cofi->ins_addr);
#ifdef DEBUG
                std::cout << "inst " << cofi_obj->inst_addr << " NOT_TAKEN, next = " << cofi_obj->next_cofi->inst_addr << std::endl;
#endif
                cofi_obj = cofi_obj->next_cofi;
                break;
            }
            break;

            case COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH: {
#ifdef DEBUG
                std::cout << "COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr << std::endl;
#endif
                uint64_t target_addr = cofi_obj->target_addr;
                assert(target_addr != 0);
                cofi_obj = get_cofi_obj(target_addr);
                break;
            }
            case COFI_TYPE_INDIRECT_BRANCH:
#ifdef DEBUG
                std::cout << "COFI_TYPE_INDIRECT_BRANCH: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr << std::endl;
#endif
                //assert(false); //not implemented.
                cofi_obj = nullptr;
                break;

            case COFI_TYPE_NEAR_RET:
#ifdef DEBUG
                std::cout << "COFI_TYPE_NEAR_RET: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr << std::endl;
#endif
                cofi_obj = nullptr;
                break;

            case COFI_TYPE_FAR_TRANSFERS:
#ifdef DEBUG
                std::cout << "COFI_TYPE_FAR_TRANSFERS: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr << std::endl;
#endif
                //assert(false); //not implemented.
                cofi_obj = nullptr;
                break;

            case NO_COFI_TYPE:
                cofi_obj = nullptr;
                break;
        }
        num_tnt_decoded ++;
        this->num_decoded_branch ++;
        if(cofi_obj != nullptr)
            alter_bitmap(cofi_obj->inst_addr);
    }

    return num_tnt_decoded;
}

uint32_t pt_packet_decoder::decode_fake_tnt(uint64_t entry_point){
    uint8_t tnt;
    uint32_t bb_count = 0;
    while( true){
        uint16_t bb = 0;
        int i;
        for(i = 0; i < 16; i ++) {
            tnt = process_tnt_cache(tnt_cache_state);
            if(tnt == TNT_EMPTY) {
                break;
            }
            if(tnt == TAKEN) {
                bb = (bb << 1) & 1;
            }
            else {
                bb = bb << 1;
            }
        }
        if(i == 0) {
            break;
        }
        else {
            alter_bitmap(bb);
            bb_count ++;
        }
    }
    return bb_count;
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

void pt_packet_decoder::dump_control_flows(FILE* f) {
    std::cout << "dump control flow inst, total inst is: " << control_flows.size() << std::endl;
    for(int i = 0; i < this->control_flows.size(); i ++) {
        fprintf(f, "%p\n", control_flows[i]);
    }
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

void pt_packet_decoder::decode(branch_info_mode_t mode) {

    if(this->aux_tail >= this->aux_head) {
        std::cerr << "failed to decode: invalid trace data: aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << std::endl;
        return;
    }

    if(this->aux_head - this->aux_tail >= get_fuzzer_config().perf_aux_size ) {
        std::cerr << "perf aux buffer full, PT packets may be truncated." << std::endl;
        std::cerr << "current perf aux buffer size is " << get_fuzzer_config().perf_aux_size << ", you may need to enlarge it." << std::endl;
        return;
    }

    this->branch_info_mode = mode;

    uint8_t* map = this->pt_packets;
    uint64_t len = this->aux_head - this->aux_tail - 1;
    uint8_t* end = map + len;
    unsigned char *p;
    uint8_t byte0;

#ifdef DEBUG
    std::cout << "try to decode packet buffer: " << (uint64_t)this->pt_packets << ", aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << ", size = " << (int64_t)len << std::endl;
#endif
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
                tnt8_handler(&p);
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
#ifdef DEBUG
                    std::cout << "append long tnt" << std::endl;
#endif
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

#ifdef DEBUG
            print_unknown(p, end);
            std::cout << "unknow pt packets." << std::endl;
#endif
            return;
        }
    }
#ifdef DEBUG
    std::cout << "all PT parckets are decoded." << std::endl;
#endif
#ifdef DEBUG
    std::cout << "number of TNT left undecoded: " << count_tnt(this->tnt_cache_state) << std::endl;
#endif

}

void pt_packet_decoder::flush(){
    this->last_tip = 0;
    this->last_ip2 = 0;
    this->isr = false;
    this->in_range = false;
    this->pkt_state.reset();
}


extern "C" {
pt_fuzzer* the_fuzzer;
void init_pt_fuzzer(char* raw_bin_file, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point){
    if(raw_bin_file == nullptr) {
        std::cerr << "raw binary file not set." << std::endl;
        exit(-1);
    }
    if(min_addr == 0 || max_addr == 0 || entry_point == 0) {
        std::cerr << "min_addr, max_addr or entry_point not set." << std::endl;
        exit(-1);
    }
    the_fuzzer = new pt_fuzzer(raw_bin_file, min_addr, max_addr, entry_point);
    the_fuzzer->init();
}
void start_pt_fuzzer(int pid){
    the_fuzzer->start_pt_trace(pid);
    the_fuzzer->start = std::chrono::steady_clock::now();
}

void stop_pt_fuzzer(uint8_t *trace_bits){
    the_fuzzer->end = std::chrono::steady_clock::now();
    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
#ifdef DEBUG
    std::cout << "Time of exec: " << the_fuzzer->diff.count()*1000000000 << std::endl;
#endif
    the_fuzzer->start = std::chrono::steady_clock::now();
    the_fuzzer->stop_pt_trace(trace_bits);
    the_fuzzer->end = std::chrono::steady_clock::now();
    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
#ifdef DEBUG
    std::cout << "Time of decode: " << the_fuzzer->diff.count()*1000000000 << std::endl;
#endif
}

}
