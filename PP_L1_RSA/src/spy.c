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
#include "../../Utils/src/performancecounters.h"
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

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

#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/l1d_prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/l1d_probe_static_analysis.data"

/* [+] BEGIN [+] Random Replacement Policy */

#define NR_OF_ADDRS 64 /*todo: change*/
#define L1D_CACHE_NR_OF_BITS_OF_OFFSET 6
//#define MEMORY_MAPPED_SIZE 10 * 1024 * 1024 //PAGES_SIZE * L1D_CACHE_NUMBER_OF_WAYS

typedef struct congruentaddrs {
	int wasaccessed;
	void *virtualaddrs[NR_OF_ADDRS];
} congruentaddrs_t;

typedef struct l1dcache {
	congruentaddrs_t congaddrs[L1D_CACHE_NUMBER_OF_SETS];
	void *l1dcachebasepointer;
	int mappedsize;
	int pagemap;
} l1dcache_t;

typedef struct evictionconfig {
	int evictionsetsize;
	int sameeviction;
	int congruentvirtualaddrs;
} evictionconfig_t;

typedef struct evictiondata {
	unsigned int maxhit;
	unsigned int maxmiss;
	int threshold;
	double countcorrecthits;
	double allhits;
	double hitsrate;
	double countcorrectmisses;
	double allmisses;
	double evictionrate;
} evictiondata_t;

void preparel1dcache(l1dcache_t **l1dcache, int mappedsize) {
	int i;

	*l1dcache = calloc(1, sizeof(l1dcache_t));
	(*l1dcache)->mappedsize = mappedsize;
	// Map l1d cache
	(*l1dcache)->l1dcachebasepointer = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*l1dcache)->l1dcachebasepointer == MAP_FAILED)
		handle_error("mmap");

	// Get file pointer for /proc/<pid>/pagemap
	(*l1dcache)->pagemap = open("/proc/self/pagemap", O_RDONLY);

	// Init mapping so that pages are not empty
	for (i = 0; i < mappedsize; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) (*l1dcache)->l1dcachebasepointer)
				+ i;
		aux[0] = i;
	}

	// Init congaddrs
	memset((*l1dcache)->congaddrs, 0,
			L1D_CACHE_NUMBER_OF_SETS * sizeof(congruentaddrs_t));
}

void prepareevictconfig(evictionconfig_t **config, int evictionsetsize,
		int sameeviction, int congruentvirtualaddrs) {
	*config = calloc(1, sizeof(evictionconfig_t));
	(*config)->evictionsetsize = evictionsetsize;
	(*config)->sameeviction = sameeviction;
	(*config)->congruentvirtualaddrs = congruentvirtualaddrs;
}

void *getphysicaladdr(void *virtualaddr, int pagemap) {
	// Access a cache line
	accessway(virtualaddr);

	// Obtain virtual addr offset within the pagemap
	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// Page map info is 64 bit size = 8 bytes = PAGEMAP_INFO_SIZE
	unsigned long virtualaddr_offset =
			((unsigned long) virtualaddr / PAGES_SIZE) * PAGEMAP_INFO_SIZE;

	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// The page frame number is in bits 0-54.
	// PAGEMAP_INFO_SIZE -1 = the first 7 bytes (bits 0-55)
	unsigned long long pageframenumber = 0;
	if (pread(pagemap, &pageframenumber, PAGEMAP_INFO_SIZE, virtualaddr_offset)
			!= 8) {
		/*NOT 8bytes*/
		handle_error("pread");
	}

	// Check page present
	if (!(pageframenumber & (1ULL << 63))) {
		handle_error("page not present");
	}

	// Data from: https://www.kernel.org/doc/Documentation/vm/pagemap.txt
	// Bit 55 is the flag pte is soft-dirty so it need to be cleared
	pageframenumber &= ((1ULL << 54) - 1);

	// Calculate the physical addr:  "| PageFramNumber | Offset of the physical addr |"
	// The offset of the physical address is = "| Index | Offset |" of the virtual addr
	return ((pageframenumber * PAGES_SIZE)
			| (((unsigned long) virtualaddr) & (PAGES_SIZE - 1)));
}

unsigned int getsetindex(void *physicaladdr) {
	return (((unsigned int) physicaladdr) >> L1D_CACHE_NR_OF_BITS_OF_OFFSET)
			% L1D_CACHE_NUMBER_OF_SETS;
}

// L1 D-Cache |Tag(20 bits)|Set(6 bits)|offset(6 bits) = |
void getphysicalcongruentaddrs(evictionconfig_t *config, l1dcache_t *l1dcache,
		unsigned int set, void *physicaladdr_src) {
	unsigned int i, count_found, index_aux;
	void *virtualaddr_aux, *physicaladdr_aux;
	const int virtualaddrslimit = config->evictionsetsize
			+ config->congruentvirtualaddrs - 1;
	count_found = 0;

	// Search for virtual addrs with the same physical index as the source virtual addr
	for (i = 0; count_found != virtualaddrslimit && i < l1dcache->mappedsize;
			i +=
			L1D_CACHE_LINE_NUMBER_OF_BYTES) {
		virtualaddr_aux = l1dcache->l1dcachebasepointer + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux, l1dcache->pagemap);
		index_aux = getsetindex(physicaladdr_aux);

		if (set == index_aux && physicaladdr_src != physicaladdr_aux) {
			l1dcache->congaddrs[set].virtualaddrs[count_found] =
					virtualaddr_aux;
			count_found++;
		}
	}
	if (count_found != virtualaddrslimit)
		handle_error("not enough congruent addresses");

	l1dcache->congaddrs[set].wasaccessed = 1;
}

void evict(evictionconfig_t *config, void *virtualaddrs[NR_OF_ADDRS]) {
	int icounter, iaccesses, icongruentaccesses;
	for (icounter = 0; icounter < config->evictionsetsize; ++icounter) {
		for (iaccesses = 0; iaccesses < config->sameeviction; ++iaccesses) {
			for (icongruentaccesses = 0;
					icongruentaccesses < config->congruentvirtualaddrs;
					++icongruentaccesses) {
				accessway(virtualaddrs[icounter + icongruentaccesses]);
			}
		}
	}
}

void primel1dcache(evictionconfig_t *config, l1dcache_t *l1dcache,
		unsigned int set, void *physicaladdr) {

	if (l1dcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, l1dcache, set, physicaladdr);
	}
	congruentaddrs_t congaddrs = l1dcache->congaddrs[set];
	evict(config, congaddrs.virtualaddrs);
}

unsigned long probel1dcache(evictionconfig_t *config, l1dcache_t *l1dcache,
		unsigned int set, void *physicaladdr) {
	//Begin measuring time
	unsigned long long start;
	start = getcurrenttsc();

	int i, addrcount = config->evictionsetsize + config->congruentvirtualaddrs
			- 1;

	if (l1dcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, l1dcache, set, physicaladdr);
	}
	congruentaddrs_t congaddrs = l1dcache->congaddrs[set];
	for (i = addrcount - 1; i >= 0; --i) {
		accessway(congaddrs.virtualaddrs[i]);
	}

	// Obtain operations time
	return getcurrenttsc() - start;
}


void obtainevictiondata(int mappedsize, int evictionsetsize, int sameeviction,
		int congruentvirtualaddrs, int histogramsize, int histogramscale,
		evictiondata_t *evictiondata) {
	int fdallh, fdallm;
	unsigned int hits, misses, l1dhits, l1dmisses;

	// Config Performance Counters
	fdallh = get_fd_perf_counter(PERF_TYPE_HARDWARE,
			PERF_COUNT_HW_CACHE_REFERENCES);
	fdallm = get_fd_perf_counter(PERF_TYPE_HARDWARE,
			PERF_COUNT_HW_CACHE_MISSES);


	// Preparing histograms
	const int MAX_RUNS = 1024 * 1024;
	const int MID_ARRAY = PAGES_SIZE / 2;
	unsigned int *hit_counts;
	hit_counts = calloc(histogramsize, sizeof(unsigned int));
	unsigned int *miss_counts;
	miss_counts = calloc(histogramsize, sizeof(unsigned int));

	int i;
	void *array, *physicaladdr;
	l1dcache_t *l1dcache;
	evictionconfig_t *config;

	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (array == MAP_FAILED)
		handle_error("mmap");

	preparel1dcache(&l1dcache, mappedsize);
	prepareevictconfig(&config, evictionsetsize, sameeviction,
			congruentvirtualaddrs);

	physicaladdr = getphysicaladdr(array + MID_ARRAY, l1dcache->pagemap);
	unsigned int set = getsetindex(physicaladdr);

	// Preparing for the hit histogram
	accessway(array + MID_ARRAY);

	// Start Hits Performance Counters
	start_perf_counter(fdallh);
	start_perf_counter(fdallm);

	// Hit histogram
	for (i = 0; i < MAX_RUNS; ++i) {
		//primel1dcache(config, l1dcache, set, physicaladdr);
		unsigned long probetime = probel1dcache(config, l1dcache, set,
				physicaladdr) / histogramscale;
		hit_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Stop Hits Performance Counters
	hits = stop_perf_counter(fdallh);
	misses = stop_perf_counter(fdallm);

	printf("\nAfter Hit Counts:\nHits: %u\n", hits);
	printf("Misses: %u\n", misses);

	// Preparing for the miss histogram
	flush(array + MID_ARRAY);

	// Start Misses Performance Counters
	start_perf_counter(fdallh);
	start_perf_counter(fdallm);

	// Miss histogram
	for (i = 0; i < MAX_RUNS; ++i) {
		primel1dcache(config, l1dcache, set, physicaladdr);
		accessway(array + MID_ARRAY);
		unsigned long probetime = probel1dcache(config, l1dcache, set,
				physicaladdr) / histogramscale;
		miss_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Stop Miss Performance Counters
	hits = stop_perf_counter(fdallh);
	misses = stop_perf_counter(fdallm);

	printf("\nAfter Miss Counts:\nHits: %u\n", hits);
	printf("Misses: %u\n", misses);


	// Obtain eviciton data
	unsigned int hitmax = 0;
	unsigned int missmax = 0;
	unsigned int hitmaxindex = 0;
	unsigned int missmaxindex = 0;
	unsigned int missminindex = 0;
//	printf("TSC:           HITS           MISSES\n");
	for (i = 0; i < histogramsize; ++i) {
//		printf("%3d: %10zu %10zu\n", i * histogramscale, hit_counts[i],
//				miss_counts[i]);
		if (hitmax < hit_counts[i]) {
			hitmax = hit_counts[i];
			hitmaxindex = i;
		}
		if (missmax < miss_counts[i]) {
			missmax = miss_counts[i];
			missmaxindex = i;
		}
		if (miss_counts[i] > 3 && missminindex == 0)
			missminindex = i;
	}

	double countcorrectmisses = 0, allmisses = 0, countcorrecthits = 0,
			allhits = 0;

	evictiondata->maxhit = hitmaxindex * histogramscale;
	evictiondata->maxmiss = missmaxindex * histogramscale;
	evictiondata->threshold = evictiondata->maxmiss
			- (evictiondata->maxmiss - evictiondata->maxhit) / 2;

	for (i = 0; i < histogramsize; ++i) {
		if (miss_counts[i] > 0
				&& (i * histogramscale) > evictiondata->threshold) {
			++countcorrectmisses;
		}
		if (miss_counts[i] > 0) {
			++allmisses;
		}
		if (hit_counts[i] > 0
				&& (i * histogramscale) < evictiondata->threshold) {
			++countcorrecthits;
		}
		if (hit_counts[i] > 0) {
			++allhits;
		}
	}
	evictiondata->allhits = allhits;
	evictiondata->allmisses = allmisses;
	evictiondata->countcorrecthits = countcorrecthits;
	evictiondata->countcorrectmisses = countcorrectmisses;
	evictiondata->evictionrate = (countcorrectmisses / allmisses) * 100;
	evictiondata->hitsrate = (countcorrecthits / allhits) * 100;

}

/* [+] END [+] Random Replacement Policy */

int main() {
	setcoreaffinity(1);

	//Uncomment when obtaining threshold
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	int i;

	// TODO Remove:
	// Paper Cache-access pattern attack on disaligned AES t-tables
	// (3/4)^(4*3) = 1.367% probability L1D Cache not being totally evicted
	const int NUMBER_TIMES_FOR_THE_TOTAL_EVICION = 3;
	int mappedsize = (L1D_CACHE_NUMBER_OF_SETS * L1D_CACHE_NUMBER_OF_WAYS * L1D_CACHE_LINE_NUMBER_OF_BYTES)*NUMBER_TIMES_FOR_THE_TOTAL_EVICION;
	for (i = 5; i < 30;++i){
		obtainevictiondata(mappedsize, i, 1, 1, /*Histogram size*/300, /*Histogram scale*/
		5, evictiondata);
		printf("\n i: %d\n",i);
		if(evictiondata->evictionrate > 50){
			if (evictiondata->maxhit >= evictiondata->maxmiss) {
				printf("[!] Cycles of Hit >= Cycles of Miss [!]\n");
			}
			printf("Max Hit: %u\n", evictiondata->maxhit);
			printf("Max Miss: %u\n", evictiondata->maxmiss);
			printf("Threshold: %u\n", evictiondata->threshold);
			printf("Hits Rate: %lf\%\n", evictiondata->hitsrate);
			printf("Eviction Rate: %lf\%\n", evictiondata->evictionrate);

		}
	}


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
