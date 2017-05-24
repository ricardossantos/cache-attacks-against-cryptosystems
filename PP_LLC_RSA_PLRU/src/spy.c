#define _GNU_SOURCE
#include <stdio.h>
#include <limits.h>
#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/fileutils.h"
#include "../../Utils/src/performancecounters.h"

#define PAGES_SIZE 4096
#define PAGEMAP_INFO_SIZE 8 /*There are 64 bits of info for each page on the pagemap*/
#define LL_CACHE_NUMBER_OF_SETS 1024
#define LL_CACHE_NUMBER_OF_WAYS 16
#define LL_CACHE_NR_OF_BITS_OF_OFFSET 6
#define LL_CACHE_LINE_NUMBER_OF_BYTES 64
#define LL_CACHE_SIZE_OF_WAY (LL_CACHE_LINE_NUMBER_OF_BYTES*LL_CACHE_NUMBER_OF_SETS)
#define MAX_TIMES_TO_CSV 300000
#define BASE_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * LL_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * LL_CACHE_SIZE_OF_WAY))
#define PREVIOUS_CACHE_LINE_PTR(baseptr,set,way) (void *)(((unsigned int)baseptr) + ((set) * LL_CACHE_LINE_NUMBER_OF_BYTES) + ((way) * LL_CACHE_SIZE_OF_WAY) + (sizeof(void *)))
#define RANDOMIZESETPTRS 0
#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"
#define MAX_TIMES_TO_OBTAIN_THRESHOLD 512*1024
#define VARIATION_ANALYSIS_DATA_FILENAME "pp_llc_hit_miss_variation_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_DIRECTORY "/home/root/thesis-code/"
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

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
	return (((unsigned int) physicaladdr) >> LL_CACHE_NR_OF_BITS_OF_OFFSET)
			% LL_CACHE_NUMBER_OF_SETS;
}

/* [+] BEGIN [+] Least Recently Used Replacement Policy <- No need to this type of attack */

typedef struct llcache {
	void *basepointer;
	void *lastpointer;
	int mappedsize;
	int pagemap;
	unsigned short int analysis[MAX_TIMES_TO_CSV * LL_CACHE_NUMBER_OF_SETS];
} llcache_t;

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

// Prepare and Prime LLC
void preparellcache(llcache_t **llcache, int mappedsize) {
	int set, way;

	*llcache = calloc(1, sizeof(llcache_t));

	// Map ll cache
	(*llcache)->basepointer = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*llcache)->basepointer == MAP_FAILED)
		handle_error("mmap");

	(*llcache)->mappedsize = mappedsize;
	(*llcache)->lastpointer = NULL;

	// Get file pointer for /proc/<pid>/pagemap
	(*llcache)->pagemap = open("/proc/self/pagemap", O_RDONLY);

	// Prepare mapping/linked list
	for (set = 0; set < LL_CACHE_NUMBER_OF_SETS; ++set) {
		for (way = 0; way < LL_CACHE_NUMBER_OF_WAYS - 1; way++) {
			// (set,way)->nextline = &(set,way+1)
			(*(void **) (BASE_CACHE_LINE_PTR((*llcache)->basepointer, set, way))) =
					BASE_CACHE_LINE_PTR((*llcache)->basepointer, set, way + 1);
			// (set,way+1)->previousline = &(set,way)
			(*(void **) (PREVIOUS_CACHE_LINE_PTR((*llcache)->basepointer, set,
					way + 1))) = PREVIOUS_CACHE_LINE_PTR(
					(*llcache)->basepointer, set, way);
		}
		// (set,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(set+1,0);
		(*(void **) (BASE_CACHE_LINE_PTR((*llcache)->basepointer, set,
				LL_CACHE_NUMBER_OF_WAYS-1))) = BASE_CACHE_LINE_PTR(
				(*llcache)->basepointer, set + 1, 0);
		// (set,0)->previousline = &(set+1,LL_CACHE_NUMBER_OF_WAYS-1);
		(*(void **) (PREVIOUS_CACHE_LINE_PTR((*llcache)->basepointer, set, 0))) =
				PREVIOUS_CACHE_LINE_PTR((*llcache)->basepointer, set + 1,
						LL_CACHE_NUMBER_OF_WAYS-1);
	}
	// (LL_CACHE_NUMBER_OF_SETS-1,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(0,0)
	(*(void **) (BASE_CACHE_LINE_PTR((*llcache)->basepointer,
			LL_CACHE_NUMBER_OF_SETS-1, LL_CACHE_NUMBER_OF_WAYS-1))) =
			BASE_CACHE_LINE_PTR((*llcache)->basepointer, 0, 0);
	// (LL_CACHE_NUMBER_OF_SETS-1,0)->previousline = &(0,LL_CACHE_NUMBER_OF_WAYS-1)
	(*(void **) (PREVIOUS_CACHE_LINE_PTR((*llcache)->basepointer,
			LL_CACHE_NUMBER_OF_SETS-1, 0))) = PREVIOUS_CACHE_LINE_PTR(
			(*llcache)->basepointer, 0, LL_CACHE_NUMBER_OF_WAYS-1);

	//Init mapping/linked list
	if (RANDOMIZESETPTRS) {
		//TODO: really necessary?
	}
}

void disposel1cache(llcache_t *llcache) {
	if (llcache->basepointer != NULL) {
		munmap(llcache->basepointer, llcache->mappedsize);
	}

	llcache->mappedsize = 0;
	llcache->basepointer = NULL;

	free(llcache);
}

unsigned int prime(llcache_t *cache, int set) {
	int way = LL_CACHE_NUMBER_OF_WAYS;
	unsigned int setcycles = 0;
	void *setpointer = BASE_CACHE_LINE_PTR(cache->basepointer, set, 0);
	void *physicaladdr;
	while (way--) {
		physicaladdr = getphysicaladdr(setpointer, cache->pagemap);
		unsigned int set2 = getsetindex(physicaladdr);
		if(set == set2){
			printf("PRIMEWAY 64B: %x\n",setpointer);
			setcycles += timeaccessway(setpointer);
			//Transverse the pointer here
			setpointer = (*(void **) setpointer);
		}
	}
	return setcycles;
}

unsigned int probe(llcache_t *llcache, int set) {
	int way = LL_CACHE_NUMBER_OF_WAYS;
	unsigned int setcycles = 0;
	void *setpointer = PREVIOUS_CACHE_LINE_PTR(llcache->basepointer, set,0);
	while (way--) {
		printf("PROBEWAY 64B: %x\n",setpointer);
		setcycles += timeaccessway(setpointer);
		//Transverse the pointer here
		setpointer = (*(void **) setpointer);
	}
	return setcycles;
}

void analysellcache(unsigned short int *out_analysis, void * llbaseptr) {
	int set, way;
	for (set = 0; set < LL_CACHE_NUMBER_OF_SETS; ++set) {
		way = LL_CACHE_NUMBER_OF_WAYS;
//		printf("--------------------------\n");
//		printf("SET 64B*6Ways: %x\n",llbaseptr);

//*out_analysis = reloadset(llbaseptr, );
		unsigned long setcycles = 0;
		while (way--) {
//			printf("WAY 64B: %x\n",llbaseptr);
			setcycles += timeaccessway(llbaseptr);
			//Transverse the pointer here
			llbaseptr = (*(void **) llbaseptr);
		}

//		if(out_analysis != NULL){
//			*out_analysis = aux < USHRT_MAX? aux : USHRT_MAX;
//
//		printf("AFTER RELOAD SET 64B*6Ways: %X\n",llbaseptr);
//		printf("Analysed UINT: %X\n",out_analysis);
//		printf("--------------------------\n");
//			out_analysis++;
//		}
	}
}

/* [+] END [+] Least Recently Used Replacement Policy <- No need to this type of attack */

void obtainevictiondata(int histogramsize, int histogramscale, int maxruns,
		evictiondata_t *evictiondata, llcache_t *cache) {

	// Preparing histograms
	const int MID_ARRAY = PAGES_SIZE / 2;
	unsigned int *hit_counts;
	hit_counts = calloc(histogramsize, sizeof(unsigned int));
	unsigned int *miss_counts;
	miss_counts = calloc(histogramsize, sizeof(unsigned int));

	int i;
	void *array, *physicaladdr;

	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (array == MAP_FAILED)
		handle_error("mmap");

	physicaladdr = getphysicaladdr(array + MID_ARRAY, cache->pagemap);
	unsigned int set = getsetindex(physicaladdr);

	// Preparing for the hit histogram
	accessway(array + MID_ARRAY);

	// Hit histogram
	for (i = 0; i < maxruns; ++i) {
		prime(cache, set);
		unsigned int probetime = probe(cache, set) / histogramscale;
		hit_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Preparing for the miss histogram
	flush(array + MID_ARRAY);

	// Miss histogram
	for (i = 0; i < maxruns; ++i) {
		prime(cache, set);

		accessway(array + MID_ARRAY);

		unsigned int probetime = probe(cache, set) / histogramscale;
		miss_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Obtain eviciton data
	unsigned int hitmax = 0;
	unsigned int missmax = 0;
	unsigned int hitmaxindex = 0;
	unsigned int missmaxindex = 0;
	unsigned int missminindex = 0;
//	printf("TSC:           HITS           MISSES\n");
	for (i = 0; i < histogramsize; ++i) {
		printf("%3d: %10zu %10zu\n", i * histogramscale, hit_counts[i],
				miss_counts[i]);
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

	//Dispose array mmap
	munmap(array, PAGES_SIZE);
}

void analysehitandmissvariation(int mappedsize, char *filename,
		int analysissize, int histogramsize, int histogramscale) {
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));

	const int headerssize = 2;
	int i;
	unsigned int analysis_array[analysissize][headerssize];

	llcache_t *cache;

	preparellcache(&cache, mappedsize);

	for (i = 0; i < analysissize; ++i) {
		obtainevictiondata(/*Histogram size*/histogramsize, /*Histogram scale*/
		histogramscale,
		MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, cache);
		analysis_array[i][0] = evictiondata->maxhit;
		analysis_array[i][1] = evictiondata->maxmiss;
	}
	const char *headers[headerssize];
	headers[0] = "Hits";
	headers[1] = "Misses";
	biarraytocsvwithstrheaders(filename, headers, analysissize, headerssize,
			analysis_array);
	disposel1cache(cache);
}

int main() {
	llcache_t *cache;
	evictiondata_t *evictiondata;
	int mappedsize, maxruns;

	const int histogramsize = 500;
	const int histogramscale = 5;
	const int analysissize = 30;

	// Paper Cache-access pattern attack on disaligned AES t-tables
	// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
	mappedsize = LL_CACHE_NUMBER_OF_SETS * LL_CACHE_NUMBER_OF_WAYS
			* LL_CACHE_LINE_NUMBER_OF_BYTES;

	maxruns = MAX_TIMES_TO_OBTAIN_THRESHOLD;
	evictiondata = calloc(1, sizeof(evictiondata_t));
	preparellcache(&cache, mappedsize);

	char filename[200] = "";
	sprintf(filename, "%s%s", VARIATION_ANALYSIS_DATA_DIRECTORY,
			VARIATION_ANALYSIS_DATA_FILENAME);

	analysehitandmissvariation(mappedsize, filename, analysissize,
			histogramsize, histogramscale);

	obtainevictiondata(histogramsize, histogramscale, maxruns, evictiondata,
			cache);
	if (evictiondata->evictionrate > 50) {
		if (evictiondata->maxhit >= evictiondata->maxmiss) {
			printf("[!] Cycles of Hit >= Cycles of Miss [!]\n");
		}
		printf("Max Hit: %u\n", evictiondata->maxhit);
		printf("Max Miss: %u\n", evictiondata->maxmiss);
		printf("Threshold: %u\n", evictiondata->threshold);
		printf("Hits Rate: %lf\%\n", evictiondata->hitsrate);
		printf("Eviction Rate: %lf\%\n", evictiondata->evictionrate);
	}
	disposel1cache(cache);
	return 0;
}
