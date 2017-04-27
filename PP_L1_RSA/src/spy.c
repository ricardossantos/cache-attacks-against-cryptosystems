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
#define PAGEMAP_INFO_SIZE 8 /*There are 64 bits of info for each page on the pagemap*/
#define L1D_CACHE_NUMBER_OF_SETS 64
#define L1D_CACHE_NUMBER_OF_WAYS 6
#define L1D_CACHE_LINE_NUMBER_OF_BYTES 64
#define L1D_CACHE_SIZE_OF_WAY (L1D_CACHE_LINE_NUMBER_OF_BYTES*L1D_CACHE_NUMBER_OF_SETS)
#define MAX_TIMES_TO_MONITOR 30000

#define BASE_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * L1D_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * L1D_CACHE_SIZE_OF_WAY))
#define PREVIOUS_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * L1D_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * L1D_CACHE_SIZE_OF_WAY) + (sizeof(void *)))

#define RANDOMIZESETPTRS 0

#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"



void delayloop(size_t cycles) {
	unsigned long long start = rdtscp();
	while ((rdtscp() - start) < cycles)
		;
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

/* [+] BEGIN [+] Least Recently Used Replacement Policy <- No need to this type of attack */

//void preparel1cache(void * basepointer) {
//	int set, way;
//
//	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
//		for (way = 0; way < L1D_CACHE_NUMBER_OF_WAYS - 1; way++) {
//			// (set,way)->nextline = &(set,way+1)
//			(*(void **) (BASE_CACHE_LINE_PTR(basepointer, set, way))) =
//					BASE_CACHE_LINE_PTR(basepointer, set, way + 1);
//			// (set,way+1)->previousline = &(set,way)
//			(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer, set, way + 1))) =
//					PREVIOUS_CACHE_LINE_PTR(basepointer, set, way);
//		}
//		// (set,L1D_CACHE_NUMBER_OF_WAYS-1)->nextline = &(set+1,0);
//		(*(void **) (BASE_CACHE_LINE_PTR(basepointer, set, L1D_CACHE_NUMBER_OF_WAYS-1))) =
//							BASE_CACHE_LINE_PTR(basepointer, set+1, 0);
//		// (set,0)->previousline = &(set+1,L1D_CACHE_NUMBER_OF_WAYS-1);
//		(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer, set, 0))) =
//				PREVIOUS_CACHE_LINE_PTR(basepointer, set+1, L1D_CACHE_NUMBER_OF_WAYS-1);
//	}
//	// (L1D_CACHE_NUMBER_OF_SETS-1,L1D_CACHE_NUMBER_OF_WAYS-1)->nextline = &(0,0)
//	(*(void **) (BASE_CACHE_LINE_PTR(basepointer, L1D_CACHE_NUMBER_OF_SETS-1,
//			L1D_CACHE_NUMBER_OF_WAYS-1))) = BASE_CACHE_LINE_PTR(basepointer, 0,
//			0);
//	// (L1D_CACHE_NUMBER_OF_SETS-1,0)->previousline = &(0,L1D_CACHE_NUMBER_OF_WAYS-1)
//	(*(void **) (PREVIOUS_CACHE_LINE_PTR(basepointer,
//			L1D_CACHE_NUMBER_OF_SETS-1, 0))) = PREVIOUS_CACHE_LINE_PTR(
//			basepointer, 0, L1D_CACHE_NUMBER_OF_WAYS-1);
//	if (RANDOMIZESETPTRS) {
//		//TODO: really necessary?
//	}
//}
//
//void analysel1dcache(unsigned short int *out_analysis, void * l1dbaseptr) {
//	int set, way;
//	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
//		way = L1D_CACHE_NUMBER_OF_WAYS;
////		printf("--------------------------\n");
////		printf("SET 64B*6Ways: %x\n",l1dbaseptr);
//
//		//*out_analysis = reloadset(l1dbaseptr, );
//		unsigned long long start = getcurrenttsc();
//		while(way--){
////			printf("WAY 64B: %x\n",l1dbaseptr);
//			accessway(l1dbaseptr);
//			//Transverse the pointer here
//			l1dbaseptr = (* (void **)l1dbaseptr);
//		}
//		unsigned short int aux = getcurrenttsc()-start;
//		if(out_analysis != NULL){
//			*out_analysis = aux < USHRT_MAX? aux : USHRT_MAX;
//
////		printf("AFTER RELOAD SET 64B*6Ways: %X\n",l1dbaseptr);
////		printf("Analysed UINT: %X\n",out_analysis);
////		printf("--------------------------\n");
//			out_analysis++;
//		}
//	}
//}
//
//void flushl1dcache(void * l1dbaseptr) {
//	int set, way;
//	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
//		way = L1D_CACHE_NUMBER_OF_WAYS;
//		while(way--){
//			flush(l1dbaseptr);
//			//Transverse the pointer here
//			l1dbaseptr = (* (void **)l1dbaseptr);
//		}
//	}
//}
/* [+] END [+] Least Recently Used Replacement Policy <- No need to this type of attack */

/* [+] BEGIN [+] Random Replacement Policy */

#define NR_OF_ADDRS 64 /*todo: change*/
#define L1D_CACHE_NR_OF_BITS_OF_OFFSET 6
#define MEMORY_MAPPED_SIZE 10 * 1024 * 1024 //PAGES_SIZE * L1D_CACHE_NUMBER_OF_WAYS

typedef struct congruentaddrs{
	int wasaccessed;
	void *virtualaddrs[NR_OF_ADDRS];
}congruentaddrs_t;

typedef struct l1dcache{
	congruentaddrs_t congaddrs[L1D_CACHE_NUMBER_OF_SETS];
	void *l1dcachebasepointer;
	FILE *pagemapfile;
}l1dcache_t;

typedef struct evictionconfig{
	int evictionsetsize;
	int sameeviction;
	int congruentvirtualaddrs;
}evictionconfig_t;

void preparel1dcache(l1dcache_t **l1dcache){
	*l1dcache = calloc(1,sizeof(l1dcache_t));
	// Map l1d cache
	(*l1dcache)->l1dcachebasepointer = mmap(0, MEMORY_MAPPED_SIZE,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*l1dcache)->l1dcachebasepointer == MAP_FAILED)
		handle_error("mmap");

	// Get file pointer for /proc/<pid>/pagemap
	(*l1dcache)->pagemapfile = fopen("/proc/self/pagemap", "rb");
}

void prepareevictconfig(evictionconfig_t **config, int evictionsetsize, int sameeviction, int congruentvirtualaddrs){
	*config = calloc(1,sizeof(evictionconfig_t));
	(*config)->evictionsetsize = evictionsetsize;
	(*config)->sameeviction = sameeviction;
	(*config)->congruentvirtualaddrs = congruentvirtualaddrs;
}

void *getphysicaladdr(void *virtualaddr, int pagemapfile){
	// Access a cache line
	accessway(virtualaddr);

	// Obtain virtual addr offset within the pagemap
	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// Page map info is 64 bit size = 8 bytes = PAGEMAP_INFO_SIZE
	unsigned long virtualaddr_offset = (unsigned long)virtualaddr / PAGES_SIZE * PAGEMAP_INFO_SIZE;

	if(fseek(pagemapfile, (unsigned long)virtualaddr_offset, SEEK_SET) != 0){
		handle_error("seek");
	}

	unsigned long long pageframenumber = 0;
	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// The page frame number is in bits 0-54.
	// PAGEMAP_INFO_SIZE -1 = the first 7 bytes (bits 0-55)
	fread(&pageframenumber, 1, PAGEMAP_INFO_SIZE -1, pagemapfile);

	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// Bit 55 is the flag pte is soft-dirty so it need to be cleared
	pageframenumber &= ((1ULL <<55)-1);

	// Calculate the physical addr:  "| PageFramNumber | Offset of the physical addr |"
	// The offset of the physical address is = "| Index | Offset |" of the virtual addr
	return ((void *) (pageframenumber * PAGES_SIZE) + (((unsigned long)virtualaddr) % PAGES_SIZE));
}

unsigned int getsetindex(void *physicaladdr){
	return (((unsigned int)physicaladdr) >> L1D_CACHE_NR_OF_BITS_OF_OFFSET) % L1D_CACHE_NUMBER_OF_SETS;
}

// L1 D-Cache |Tag(20 bits)|Set(6 bits)|offset(6 bits) = |
void getphysicalcongruentaddrs(evictionconfig_t *config, l1dcache_t *l1dcache, unsigned int set){
	unsigned int i, count_found, index_aux;
	void *physicaladdr_src, *virtualaddr_aux, *physicaladdr_aux;
	const int virtualaddrslimit = config->evictionsetsize + config->congruentvirtualaddrs -1;
	count_found = 0;

	// Search for virtual addrs with the same physical index as the source virtual addr
	for(i = 0; count_found != virtualaddrslimit && i < MEMORY_MAPPED_SIZE; i+=L1D_CACHE_LINE_NUMBER_OF_BYTES){
		virtualaddr_aux = l1dcache->l1dcachebasepointer + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux,l1dcache->pagemapfile);
		index_aux = getsetindex(physicaladdr_aux);

		if(set == index_aux && physicaladdr_src != physicaladdr_aux){
			l1dcache->congaddrs[set].virtualaddrs[count_found++] = virtualaddr_aux;
		}
	}
	if(count_found != virtualaddrslimit)
		handle_error("not enough congruent addresses");

	l1dcache->congaddrs[set].wasaccessed = 1;
}

void evict(evictionconfig_t *config, void *virtualaddrs[NR_OF_ADDRS]){
	 int icounter,iaccesses,icongruentaccesses;
	 for(icounter=0; icounter < config->evictionsetsize; ++icounter) {
		 for(iaccesses=0; iaccesses < config->sameeviction;++iaccesses){
			 for(icongruentaccesses=0; icongruentaccesses< config->congruentvirtualaddrs; ++icongruentaccesses){
				 accessway(virtualaddrs[icounter + icongruentaccesses]);
			 }
		 }
	 }
}

void primel1dcache(evictionconfig_t *config, l1dcache_t *l1dcache, unsigned int set){

	if(l1dcache->congaddrs[set].wasaccessed == 0){
		getphysicalcongruentaddrs(config, l1dcache, set);
	}
	congruentaddrs_t congaddrs = l1dcache->congaddrs[set];
	evict(config, congaddrs.virtualaddrs);
}

unsigned long probel1dcache(evictionconfig_t *config, l1dcache_t *l1dcache, unsigned int set){
	//Begin measuring time
	unsigned long long start;
	start = getcurrenttsc();

	int i, addrcount = config->evictionsetsize + config->congruentvirtualaddrs -1;
	congruentaddrs_t congaddrs = l1dcache->congaddrs[set];

	if(congaddrs.wasaccessed == 0){
		getphysicalcongruentaddrs(config, l1dcache, set);
	}

	for(i=addrcount-1;i >=0;--i){
		accessway(congaddrs.virtualaddrs[i]);
	}

	// Obtain operations time
	return getcurrenttsc() - start;
}

void analysel1dcache2(unsigned short int *out_analysis, l1dcache_t *l1dcache){

}

unsigned long obtainthreshold(int evictionsetsize, int sameeviction, int congruentvirtualaddrs, int histogramscale) {
	const int MAX_RUNS = 1024*1024/*1024*1024*/;
	const int MAX_TIME = 80;
	const int MID_ARRAY = PAGES_SIZE/2;
	unsigned int *hit_counts;
	hit_counts = calloc(MAX_TIME, sizeof(unsigned int));
	unsigned int *miss_counts;
	miss_counts = calloc(MAX_TIME, sizeof(unsigned int));

	int i;
	void *array,*physicaladdr;
	l1dcache_t *l1dcache;
	evictionconfig_t *config;

	array = mmap(0, PAGES_SIZE,PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (array == MAP_FAILED)
		handle_error("mmap");

	preparel1dcache(&l1dcache);
	prepareevictconfig(&config, evictionsetsize, sameeviction, congruentvirtualaddrs);

	physicaladdr = getphysicaladdr(array+MID_ARRAY,l1dcache->pagemapfile);
	unsigned int set = getsetindex(physicaladdr);

	// Preparing for the hit histogram
	accessway(array+MID_ARRAY);

	// Hit histogram
	for(i=0; i < MAX_RUNS; ++i){
		primel1dcache(config, l1dcache, set);
		unsigned long probetime = probel1dcache(config, l1dcache, set)/histogramscale;
		hit_counts[(MAX_TIME - 1) > probetime ? probetime : MAX_TIME - 1]++;
		sched_yield();
	}

	// Preparing for the miss histogram
	flush(array+MID_ARRAY);

	// Miss histogram
	for(i=0; i < MAX_RUNS; ++i){
		primel1dcache(config, l1dcache, set);
		accessway(array+MID_ARRAY);
		unsigned long probetime = probel1dcache(config, l1dcache, set)/histogramscale;
		miss_counts[(MAX_TIME - 1) > probetime ? probetime : MAX_TIME - 1]++;
		sched_yield();
	}

	// Prepare histogram
	unsigned int hit_max = 0;
	unsigned int hit_max_index = 0;
	unsigned int miss_min_index = 0;
	printf("TSC:           HITS           MISSES\n");
	for (i = 0; i < MAX_TIME; ++i) {
		printf("%3d: %10zu %10zu\n", i * histogramscale, hit_counts[i], miss_counts[i]);
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
	return threshold * histogramscale;
}

/* [+] END [+] Random Replacement Policy */

int main() {
	setcoreaffinity(1);

	//Uncomment when obtaining threshold
	printf("\nThreshold: %lu\n", obtainthreshold(21,1,6,/*Histogram scale*/40));

//	int i;
//	void * basepointer;
//	unsigned short int *l1d_analysis, *aux;
//
//
//	printf("LIST BASE PTR AFTER PREPARE: %X",basepointer);
//	//1st and 2nd state
//	preparel1cache(basepointer);
//	printf("LIST BASE PTR AFTER PREPARE: %X",basepointer);
//
//	//3rd state
//	//[MAX_TIMES_TO_MONITOR][L1D_CACHE_NUMBER_OF_SETS];
//	l1d_analysis = (unsigned short *) calloc(
//			MAX_TIMES_TO_MONITOR * (L1D_CACHE_NUMBER_OF_SETS*2),
//			sizeof(unsigned short));
//
//	//delayloop()
//	aux = l1d_analysis;
//	for (i = 0; i < MAX_TIMES_TO_MONITOR; i+=2){
//
//		//Prime
//		analysel1dcache(aux, BASE_CACHE_LINE_PTR(basepointer, 0, 0));
//		aux += L1D_CACHE_NUMBER_OF_SETS;
//		//Probe
//		analysel1dcache(aux,
//				PREVIOUS_CACHE_LINE_PTR(basepointer, 0,
//						L1D_CACHE_NUMBER_OF_WAYS-1));
//
//		aux += L1D_CACHE_NUMBER_OF_SETS;
//	}
//	arraytodatafile(PRIME_ANALYSIS_DATA_FILENAME, PROBE_ANALYSIS_DATA_FILENAME,
//			l1d_analysis, MAX_TIMES_TO_MONITOR/2, L1D_CACHE_NUMBER_OF_SETS);

	return 0;
}
