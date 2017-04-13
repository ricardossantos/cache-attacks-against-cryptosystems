#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <sched.h>
#include <pthread.h>
#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/fileutils.h"

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define PAGES_SIZE 4096
#define L1D_CACHE_NUMBER_OF_SETS 64
#define L1D_CACHE_NUMBER_OF_WAYS 6
#define L1D_CACHE_LINE_NUMBER_OF_BYTES 64
#define L1D_CACHE_SIZE_OF_WAY (L1D_CACHE_LINE_NUMBER_OF_BYTES*L1D_CACHE_NUMBER_OF_SETS)
#define MAX_TIMES_TO_MONITOR 50000

#define BASE_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * L1D_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * L1D_CACHE_SIZE_OF_WAY))
#define PREVIOUS_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * L1D_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * L1D_CACHE_SIZE_OF_WAY) + (sizeof(void *)))

#define RANDOMIZESETPTRS 0

#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"
//Silvermont:
//L1 D-Cache is a 24KB, 6 way associative with 64B lines.
//			375 cache lines. 62.5 lines within each set (the same as number of sets.
//			Number of sets is 375/6
//L1 I-Cache is a 32KB, 8 way associative with 64B lines.
//			500 cache lines. 62.5 lines within each set.
//L2 Cache is 1MB, 16 associative and 32B/cycle bandwidth shared by the 2 cores.

int setcoreaffinity(int core_id) {
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	if (core_id < 0 || core_id >= num_cores)
		handle_error("Wrong core id");
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);
	return sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

void preparel1cache(void * basepointer) {
	int set, way;

	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
		for (way = 0; way < L1D_CACHE_NUMBER_OF_WAYS - 1; way++) {
			// (set,way)->nextline = &(set,way+1)
			(*(void **) (BASE_CACHE_LINE_PTR(basepointer, set, way))) =
					BASE_CACHE_LINE_PTR(basepointer, set, way + 1);
			// (set,way+1)->previousline = &(set,way)
			(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer, set, way + 1))) =
					BASE_CACHE_LINE_PTR(basepointer, set, way);
		}
		// (set,L1D_CACHE_NUMBER_OF_WAYS-1)->nextline = &(set+1,0);
		(*(void **) (BASE_CACHE_LINE_PTR(basepointer, set, L1D_CACHE_NUMBER_OF_WAYS-1))) =
							BASE_CACHE_LINE_PTR(basepointer, set+1, 0);
		// (set,0-1)->previousline = &(set+1,L1D_CACHE_NUMBER_OF_WAYS-1);
		(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer, set, 0))) =
							BASE_CACHE_LINE_PTR(basepointer, set+1, L1D_CACHE_NUMBER_OF_WAYS-1);
	}
	// (L1D_CACHE_NUMBER_OF_SETS-1,L1D_CACHE_NUMBER_OF_WAYS-1)->nextline = &(0,0)
	(*(void **) (BASE_CACHE_LINE_PTR(basepointer, L1D_CACHE_NUMBER_OF_SETS-1,
			L1D_CACHE_NUMBER_OF_WAYS-1))) = BASE_CACHE_LINE_PTR(basepointer, 0,
			0);
	// (L1D_CACHE_NUMBER_OF_SETS-1,0)->previousline = &(0,L1D_CACHE_NUMBER_OF_WAYS-1)
	(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer,
			L1D_CACHE_NUMBER_OF_SETS-1, 0))) = PREVIOUS_CACHE_LINE_PTR(
			basepointer, 0, L1D_CACHE_NUMBER_OF_WAYS-1);
	if (RANDOMIZESETPTRS) {
		//TODO: really necessary?
	}
}

void analysel1dcache(unsigned short int *out_analysis, void * l1dbaseptr) {
	int set, way;
	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
		way = L1D_CACHE_NUMBER_OF_WAYS;
//		printf("--------------------------\n");
//		printf("SET 64B*6Ways: %X\n",l1dbaseptr);

		//*out_analysis = reloadset(l1dbaseptr, );
		unsigned long long start = getcurrenttsc();
		while(way--){
//			printf("WAY 64B: %X\n",l1dbaseptr);
			accessway(l1dbaseptr);
			//Transverse the pointer here
			l1dbaseptr = (* (void **)l1dbaseptr);
		}
		unsigned short int aux = getcurrenttsc()-start;
		*out_analysis = aux < USHRT_MAX? aux : USHRT_MAX;

//		printf("AFTER RELOAD SET 64B*6Ways: %X\n",l1dbaseptr);
//		printf("Analysed UINT: %X\n",out_analysis);
//		printf("--------------------------\n");
		out_analysis++;
	}
}

void delayloop(size_t cycles) {
	unsigned long long start = rdtscp();
	while ((rdtscp() - start) < cycles)
		;
}

int main() {
	setcoreaffinity(1);

	int i;
	void * basepointer;
	unsigned short int *l1d_analysis, *aux;

	basepointer = mmap(0, PAGES_SIZE * L1D_CACHE_NUMBER_OF_WAYS,
	PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (basepointer == MAP_FAILED)
		handle_error("mmap");
	printf("LIST BASE PTR AFTER PREPARE: %X",basepointer);
	//1st and 2nd state
	preparel1cache(basepointer);
	printf("LIST BASE PTR AFTER PREPARE: %X",basepointer);
	//3rd state
	//[MAX_TIMES_TO_MONITOR][L1D_CACHE_NUMBER_OF_SETS];
	l1d_analysis = (unsigned short int *) calloc(
			MAX_TIMES_TO_MONITOR * L1D_CACHE_NUMBER_OF_SETS,
			sizeof(unsigned short int));

	//delayloop()
	aux = l1d_analysis;
	for (i = 0; i < MAX_TIMES_TO_MONITOR; ++i) {
		printf("%d\n",i);
		//Prime
		analysel1dcache(aux, BASE_CACHE_LINE_PTR(basepointer, 0, 0));
		aux += L1D_CACHE_NUMBER_OF_SETS;
		//Probe
		analysel1dcache(aux,
				PREVIOUS_CACHE_LINE_PTR(basepointer, L1D_CACHE_NUMBER_OF_SETS-1,
						L1D_CACHE_NUMBER_OF_WAYS-1));
		aux += L1D_CACHE_NUMBER_OF_SETS;
	}
	arraytodatafile(PRIME_ANALYSIS_DATA_FILENAME, PROBE_ANALYSIS_DATA_FILENAME,
			l1d_analysis, MAX_TIMES_TO_MONITOR, L1D_CACHE_NUMBER_OF_SETS);

	return 0;
}
