#include "pt.h"

uint64_t min_addr_cle, max_addr_cle, entry_point_cle;
uint8_t* raw_bin_buf;
uint8_t * trace_bits;                /* SHM with instrumentation bitmap  */

bool read_min_max()
{
    FILE *fp;
    int MAX_LINE_T = 1024;
    char strLine[MAX_LINE_T];
    char* endptr;

    min_addr_cle = 0ULL;
    max_addr_cle = 0ULL;
    entry_point_cle = 0ULL;

    if((fp = fopen("../min_max.txt","r")) == NULL)
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
    FILE* pt_file = fopen("../raw_bin", "rb");

    raw_bin_buf = malloc(max_addr_cle - min_addr_cle);
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

int main()
{
	int status;
	run_t run = {
        	.pid = 0,
        	.persistentPid = 0,
        	.persistentSock = -1,
        	.tmOutSignaled = false
    	};
    ;

	if(perf_init() == false)   //!!guy!!初始化tracebits并判断intel_pt对应的perf类型
	{
		printf("Initial failed\n");
		exit(1);
	}

    //read min_max.txt
    if(read_min_max() == false)
    {
        printf("Open min_max.txt Falied!");
        exit(1);
    }

    // read raw_bin from file
    if(read_raw_bin() == false)
    {
        printf("Error:Open raw_bin.txt file fail!\n");
        exit(1);
    }

    //init decoder and disassembler
    run.decoder = pt_decoder_init(raw_bin_buf, min_addr_cle, max_addr_cle, &pt_bitmap);
    if(run.decoder == NULL)
    {
        printf("Decoder struct init failed!\n");\
		exit(1);
    }




    pid_t pid;        //进程标识符
	pid = fork();     //创建一个新的进程
	if(pid<0)
	{
		printf("创建进程失败!");
		exit(1);
	}
	else if(pid==0)   //如果pid为0则表示当前执行的是子进程
	{
		printf("这是子进程,进程标识符是%d\n",getpid());
		//执行ls
		printf("execv\n");
		sleep(1);
		execv("/home/guy/ptfuzzer/afl-pt/ptest/readelf", "-a /home/guy/ptfuzzer/afl-pt/ptest/in/small_exec.elf");
		//printf("execv\n");
		sleep(1);
		exit(0);
	}
	
	else          //否则为父进程
	{
		printf("这是父进程,进程标识符是%d\n",getpid());
		
		if(perf_config(pid, &run) == false)
		{
			printf("Config failed\n");
			exit(1);
		}
		
		if(waitpid(pid, &status, 0) <= 0)
		{
			perror("Error: ");
			exit(1);
		}
		
		if(perf_reap(&run) == false)
		{
			printf("Analyze pt failed\n");
			exit(1);
		}
        uint8_t * pt_trace_bits;
        pt_trace_bits = get_trace_bits();

        memcpy(trace_bits, pt_trace_bits, MAP_SIZE);
        bool flag = 0;
        for(int i = 0; i < MAP_SIZE; i++) {
            //printf("%u", trace_bits[i]);
            if(trace_bits[i] == 1)
            {
                flag = 1;
            }
        }
        printf("\n\n");
        printf("%d\n", flag);
	}
	
	return 0;
}
