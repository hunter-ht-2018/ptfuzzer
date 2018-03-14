
#每次重启系统后，需要打开系统性能开关，使用su进入root用户，输入以下命令

echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor

#修改pt后，运行install_pt.sh脚本进行pt编译安装和afl-fuzz的重新编译


#使用以下命令进行fuzz

cd afl-pt
sudo ./afl-fuzz -t 999999 -i ./ptest/in -o ./ptest/out ./ptest/readelf -a @@ 
