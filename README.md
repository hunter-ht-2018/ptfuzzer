# PTfuzzer

## Introduction
* 中文简介[FreeBuf-PTFuzzer：一个基于硬件加速的二进制程序Fuzz工具](https://www.freebuf.com/sectool/177578.html)

* **Binary-only fuzzing.** We propose a new greybox fuzzer to fuzz any binaryonly softwares and  do not need any source code. In situations where source code is unavailable, compile-time instrumentation and thorough program
analysis is impossible, and fuzzers like AFL, AFLFast and VUzzer will be of
no use. Our approach can gracefully handle these situations and fuzz binaries
as usual.
* **Fast feedback mechanism.** We introduce a much faster feedback mechanism. As mentioned above, though previous works tried hard to solve the problem of source code reliance, they all suffer from considerable performance overhead, especially QAFL and TriforceAFL. We utilize fast hardware feedback directly from CPU, and  deal with binary-only fuzzing in a faster way than QAFL. The performance overhead of our fuzzer is smaller than QAFL according to our experiments.
* **Accurate coverage feedback.** We propose a more accurate measurement for code coverage feedback. Compile-time instrumentation and random id assignment of basic blocks will measure code coverage inaccurately. We use actual run-time addresses of basic blocks to trace transitions between basic blocks and can provide real control flow information of running code.
* **PTfuzzer.** We implement a prototype called PTfuzzer based on these insights. And our experiments show that PTfuzzer can deal with binary-only fuzzing quickly and accurately.

## Requirements

* Linux kernel >= 4.13.0. (Ubuntu 16.04.4 is OK in our test.)
* Intel CPU i5/6/7-x000, x >= 5
* libcapstone
* python-cle

You may use check-dep.sh to install the dependent packets.

## How to install

```
cd ptfuzzer/
mkdir build
cd build
cmake ../ -DPREFIX=.
make
make install 
```
This will install all python scripts and binary files to *bin* in the current directory.


## Linux kernel versions

A linux kernel of 4.13 or 4.14 is recommended.

If a kernel >= 4.15 is used, the kernel has to be booted with the "nopti" option.
Beginning with 4.15 page table isolation was introduced to protect against meltdown/spectre attacks which prevents intel_pt to trace a specific process if active.

Using a kernel <= 4.9 is not recommended as the intel_pt support is incomplete


## How to run

* You need to open the performance switch of the system everytime you reboot the system or simply run **config-run.sh**.
```
su
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```


* Prepare a your own target program and initial seed files
```
cd ptfuzzer/build
python ./bin/ptfuzzer.py "-i your/input/directory -o your/output/directory" "your/target/program -arguement"
```
* e.g. python ./bin/ptfuzzer.py "-i ./test/in -o ./test/out" "./test/readelf -a"
* Please refer to ptfuzzer/afl-pt/doc/ if you need more information and about AFL arguements

## Configurate runtime parameters

You can edit a config file to control the runtime parameters of ptfuzzer. The config file must be named ptfuzzer.conf, and it can be put in the current working directory or /etc/. Here is an example:
```
#BRANCH_MODE=TNT_MODE
BRANCH_MODE=TIP_MODE
MEM_LIMIT=100            # afl -m argument
PERF_AUX_BUFFER_SIZE=32  # the size of buffer used to store PT packets.
```
*BRANCH_MODE* controls the methods ptfuzzer uses to collect branch information. In TIP_MODE, only the control flow change encoded in the TIP packets are recorded, while TNT_MODE also includes the conditional branch encoded in the TNT packets.

*MEM_LIMIT* controls the memory limits of the target program. It is the "-m" arguments passed to afl.

*PERF_AUX_BUFFER_SIZE* controls the size of buffer ptfuzzer allocates for storing PT packest. The PT packets may be truncated if the buffer size is not big enough. 

## Unsolved Issues
+ No instrumentation detected. Unclear causes. [Issue#18](https://github.com/hunter-ht-2018/ptfuzzer/issues/18)
+ Assertion falied. Unclear causes. [Issue#15](https://github.com/hunter-ht-2018/ptfuzzer/issues/15)
+ Parallize PT decoding process. [Issue#12](https://github.com/hunter-ht-2018/ptfuzzer/issues/12)
+ No support for several programs. [Issue#8](https://github.com/hunter-ht-2018/ptfuzzer/issues/8)
+ May crash on first seed. [Issue#7](https://github.com/hunter-ht-2018/ptfuzzer/issues/7)
+ To be continue...
