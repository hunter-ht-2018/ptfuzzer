#include "pt.h"
int main()
{
	pid_t pid = 0;
	scanf("%d", &pid);
	run_t run = {
        .pid = 0,
        .persistentPid = 0,
        .persistentSock = -1,
        .tmOutSignaled = false,
    };

	perf_init();
	perf_config(pid, &run);
	perf_reap(&run);
}
