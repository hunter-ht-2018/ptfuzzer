echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
sudo modprobe msr
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor


