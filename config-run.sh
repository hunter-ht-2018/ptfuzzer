#!/bin/bash

#test "$UID" != 0 && { echo Error: must be run as root ; exit 1 ; }

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
sudo modprobe msr
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

VER=`uname -r | sed 's/\.[0-9]*-.*//'`
MAJOR=${VER//.*/}
MINOR=${VER:2:6}
case "$MAJOR" in
  [1-3]) echo Error: kernel too old: $VER ;;
  [5-9]) echo Warning: unknown kernel version: $VER ;;
  4)  if [ "$MINOR" -lt 10 ]; then echo Warning: a kernel 4.10 to 4.14 is recommended; else
         if [ "$MINOR" -gt 14 ]; then
            BOOT=`dmesg | grep 'BOOT_IMAGE'`
            if [ -z "$BOOT" ]; then echo Warning: could not determine kernel boot options, ensure you are booting with \"nopti\"; else
               echo " $BOOT " | grep -qw nopti || echo Error: you must boot your kernel with the \"nopti\" option
            fi
         fi
      fi ;;
  *) echo Error: could not determine kernel version: $VER ;;
esac
