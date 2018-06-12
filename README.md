# PTfuzzer

## Introduction

* **Binary-only fuzzing.** We propose a new greybox fuzzer to fuzz any binaryonly softwares and  do not need any source code. In situations where source code is unavailable, compile-time instrumentation and thorough program
analysis is impossible, and fuzzers like AFL, AFLFast and VUzzer will be of
no use. Our approach can gracefully handle these situations and fuzz binaries
as usual.
* **Fast feedback mechanism.** We introduce a much faster feedback mechanism. As mentioned above, though previous works tried hard to solve the problem of source code reliance, they all suffer from considerable performance overhead, especially QAFL and TriforceAFL. We utilize fast hardware feedback directly from CPU, and  deal with binary-only fuzzing in a faster way than QAFL. The performance overhead of our fuzzer is smaller than QAFL according to our experiments.
* **Accurate coverage feedback.** We propose a more accurate measurement for code coverage feedback. Compile-time instrumentation and random id assignment of basic blocks will measure code coverage inaccurately. We use actual run-time addresses of basic blocks to trace transitions between basic blocks and can provide real control flow information of running code.
* **PTfuzzer.** We implement a prototype called PTfuzzer based on these insights. And our experiments show that PTfuzzer can deal with binary-only fuzzing quickly and accurately.

## Requirements

* linux kernel >= 4.7.0
* Intel CPU i5/6/7-x000, x >= 5
* libcapstone
* python-cle

## How to install

```
cd ptfuzzer/
mkdir build
cd build
cmake ../
make
make install # install all scripts and binary files to *bin* in the current directory.
```
## How to run

* You need to open the performance switch of the system everytime you reboot the system.
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
