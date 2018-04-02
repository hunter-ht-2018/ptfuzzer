# PTfuzzer

## Introduction
We concentrate on greybox fuzzing to expose bugs and vulnerabilities in softwares. We examine previous greybox fuzzers and find out some common drawbacks of them. Some fuzzers such as AFL cannot support binary-only fuzzing, some has low code coverage and some suffer from huge overhead, such as AFL QEMU. To address these limitations, we introduce a greybox fuzzing technique assisted by Intel Processor Trace technology and implement a prototype called PTfuzzer. We accurately record basic block transitions in program execution with PT in a relatively fast execution speed, and achieve higher code coverage than previous fuzzers. And experiment results demonstrate that PTfuzzer outperforms AFL and QAFL in most of the 3 indicators, crashes, speed, and branches. The result is a strong evidence that PTfuzzer is much more effective in fuzzing jobs and is able to expose deeper bugs and vulnerabilities in programs.
	
***
	
## Motivation
Recent works about greybox fuzzing have some common limitations.
We can list three drawbacks of previous works as follows:


* **No binary-only fuzzing support**. Greybox fuzzers like AFL, AFLFast and VUzzer all rely on source code of target programs. AFL and AFLFast use bitmap to trace basic block transitions and code coverage. Each basic block has a randomly assigned id from compile-time instrumentation. And this kind of instrumentation CANNOT be done without source code. The same goes for VUzzer, because it analyzes programs with control- and data-flow features from  static and dynamic analysis. VUzzer is a typical application-aware fuzzing technique. Fuzzers without binary-only support cannot be adopted to situations where compile-time instrumentation or source code is unavailable. Unfortunately, many software vendors prefer not to provide source code of their softwares. This makes fuzzers without binary-only support valueless in detecting vulnerabilities and bugs.

* **Slow feedback mechanism**. In order to solve the problem of dependence
on compile-time instrumentation and source code, several feedback mechanisms such as  dynamic binary instrumentation (Intel PIN), static rewriting (AFL-dyninst), and emulation (QEMU)  are introduced in fuzzing. As we have mentioned, AFL is extended with QEMU emulation (we refer it as QAFL). Later works such as TriforceAFL, also adopt QEMU to fuzz operating systems. However, the author of AFL, Michal Zalewski, pointed out that  the usual performance cost of QEMU in fuzzing is 2-5x. The reason for such cost is out of our research scope in this paper. Definitely, such performance  overhead due to slow feedback mechanism is intolerable in our fuzzing practice. There is an urgent desire to improve these slow mechanisms.


* **Inaccurate coverage feedback.** As mentioned above, greybox fuzzers like
AFL and AFLFast use bitmap to trace basic block transitions and measure code coverage. The id of block A and B is randomly assigned through runtime instrumentation. Transition from  block A to block B is assigned an offset into the bitmap as (A ⊕ B)%BITMAP SIZE (⊕ means XOR operation). AFL uses this method to make the bitmap small so that it can reside in cache to improve performance. However, let us assume that there is a transition edge from A to B and another edge from C to D. When id of A and C is randomly assigned the same value, and B and D is also the same, these two different block transitions will be considered the same, which we call collision or overlap. In this situation, if transition from A to B is not new, and C to D is a new path that has never been hit before, test cases which can trigger transition C to D will not be saved as a new seed. So the fuzzing loop may lose some important seeds, may be incomplete and cannot reach deep paths in programs.

***

## Contribution of PTfuzzer:
* **Binary-only fuzzing.** We propose a new greybox fuzzer to fuzz any binaryonly softwares and  do not need any source code. In situations where source code is unavailable, compile-time instrumentation and thorough program
analysis is impossible, and fuzzers like AFL, AFLFast and VUzzer will be of
no use. Our approach can gracefully handle these situations and fuzz binaries
as usual.
* **Fast feedback mechanism.** We introduce a much faster feedback mechanism. As mentioned above, though previous works tried hard to solve the problem of source code reliance, they all suffer from considerable performance overhead, especially QAFL and TriforceAFL. We utilize fast hardware feedback directly from CPU, and  deal with binary-only fuzzing in a faster way than QAFL. The performance overhead of our fuzzer is smaller than QAFL according to our experiments.
* **Accurate coverage feedback.** We propose a more accurate measurement for code coverage feedback. Compile-time instrumentation and random id assignment of basic blocks will measure code coverage inaccurately. We use actual run-time addresses of basic blocks to trace transitions between basic blocks and can provide real control flow information of running code.
* **PTfuzzer.** We implement a prototype called PTfuzzer based on these insights. And our experiments show that PTfuzzer can deal with binary-only fuzzing quickly and accurately.

## How to install
```shell
cd ptfuzzer/
sudo ./check_dep.sh
./install_pt.sh
```
## How to run

You need to open the performance switch of the system everytime you reboot the system.
```
su
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```


* Prepare a your own target program and initial seed files
* cd ptfuzzer/afl-pt/
* sudo ./afl-fuzz -i your/input/directory -o your/output/directory your/target/program -parameter @@
* (e.g. sudo ./afl-fuzz -i readelf_in -o readelf_out readelf -a @@)
* Please refer to ptfuzzer/afl-pt/doc/ if you need more information