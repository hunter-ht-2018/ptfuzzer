/*
 * Utility to read CPUIDs from x86 processors
 * Copyright (c) 2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct cpuid {
	uint32_t eax, ebx, ecx, edx;
};

static int cpuid(int cpu, uint32_t leaf, uint32_t subleaf, struct cpuid *data)
{
	static int fd = -1;
	static int last_cpu;
	off_t offset = leaf + ((off_t) subleaf << 32);

	if (fd < 0 || last_cpu != cpu) {
		char devstr[64];
		if (fd >= 0)
			close(fd);
		snprintf(devstr, sizeof devstr, "/dev/cpu/%d/cpuid", cpu);
		fd = open(devstr, O_RDONLY);
		if (fd < 0) {
			if (errno == ENXIO) {
				fprintf(stderr, "cpuid: No CPU %d\n", cpu);
				exit(2);
			} else if (errno == EIO) {
				fprintf(stderr,
					"cpuid: CPU %d doesn't support cpuid\n",
					cpu);
				exit(3);
			} else {
				perror("cpuid: open");
				exit(127);
			}
		}
		last_cpu = cpu;
	}
	return pread(fd, data, sizeof(*data), offset) == sizeof(*data) ? 0 : -1;
}

static char *make_string(uint32_t val)
{
	static char string[5] = "xxxx";
	int i, ch;

	for (i = 0; i < 4; i++) {
		ch = val & 0xff;
		string[i] = isprint(ch) ? ch : '.';
		val >>= 8;
	}

	return string;
}

static void print_cpuid_level(uint32_t leaf, uint32_t subleaf,
			      struct cpuid *lvl)
{
	printf("%08x %08x:  ", leaf, subleaf);
	printf("%08x %s  ", lvl->eax, make_string(lvl->eax));
	printf("%08x %s  ", lvl->ebx, make_string(lvl->ebx));
	printf("%08x %s  ", lvl->ecx, make_string(lvl->ecx));
	printf("%08x %s\n", lvl->edx, make_string(lvl->edx));
}

static void dump_cpuid_leaf(int cpu, uint32_t leaf)
{
	struct cpuid lvl, lastlvl, lvl0;
	uint32_t subleaf;

	cpuid(cpu, leaf, 0, &lvl0);
	print_cpuid_level(leaf, 0, &lvl0);

	/*
	 * There is no standard mechanism for enumerating the number of
	 * subleaves, this is a heuristic...
	 */
	lastlvl = lvl0;

	for (subleaf = 1; subleaf != 0; subleaf++) {
		if (cpuid(cpu, leaf, subleaf, &lvl))
			return;

		switch (leaf) {
		case 4:
			if ((lvl.eax & 0x1f) == 0
			    || !memcmp(&lvl, &lastlvl, sizeof lvl))
				return;
			break;

		case 7:
			if (subleaf >= lvl0.eax)
				return;
			break;

		case 0xb:
			if ((lvl.ecx & ~0xff) == 0)
				return;

		case 0xd:
			if ((lvl.eax | lvl.ebx | lvl.ecx | lvl.edx) == 0)
				return;

		default:
			/* Generic, anticipatory rules */
			/* Exclude ecx here for levels which return the initial ecx value */
			if ((lvl.eax | lvl.ebx | lvl.ecx | lvl.edx) == 0)
				return;

			if (!memcmp(&lvl, &lvl0, sizeof lvl))
				return;
			break;
		}

		print_cpuid_level(leaf, subleaf, &lvl);

		lastlvl = lvl;
	}
}

static void dump_levels(int cpu, uint32_t region)
{
	static struct cpuid invalid_leaf;
	struct cpuid max;
	uint32_t n;

	if (cpuid(cpu, region, 0, &max))
		return;

	/*
	 * Intel processors may return the last group 0 CPUID leaf instead
	 * all zero for a not-present level
	 */
	if (region == 0) {
		cpuid(cpu, max.eax + 1, 0, &invalid_leaf);
	} else {
		if (!memcmp(&max, &invalid_leaf, sizeof(struct cpuid)))
			return;
	}

	if ((max.eax & 0xffff0000) == region) {
		for (n = region; n <= max.eax; n++) {
			dump_cpuid_leaf(cpu, n);
		}
	}
}

void usage(void)
{
	fprintf(stderr, "Usage: cpuid [processor # (default 0)]\n");
}

int main(int argc, char *argv[])
{
	int cpu = 0;
	uint32_t n;
	char *endptr;

	if (argc > 2) {
		usage();
		exit(127);
	} else if (argc == 2) {
		cpu = strtoul(argv[1], &endptr, 0);
		if (*endptr || cpu > 255) {
			usage();
			exit(127);
		}
	}

	printf
	    ("Leaf     Subleaf    EAX            EBX            ECX            EDX            \n");

	for (n = 0; n <= 0xffff; n++) {
		dump_levels(cpu, n << 16);
	}

	return 0;
}
