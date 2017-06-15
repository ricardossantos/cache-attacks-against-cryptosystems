#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/performancecounters.h"
#include "../../Utils/src/fileutils.h"

#define PAGES_SIZE 4096
#define NR_OF_ADDRS 512
#define CACHE_NR_OF_BITS_OF_OFFSET 6
#define CACHE_LINE_NUMBER_OF_BYTES 64
#define PAGEMAP_INFO_SIZE 8 /*There are 64 bits of info for each page on the pagemap*/
#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_FILENAME "pp_llc_hit_miss_variation_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_DIRECTORY "/home/root/thesis-code/"
#define MAX_TIMES_TO_CSV 300000
#define MAX_TIMES_TO_OBTAIN_THRESHOLD 512*1024
#define OUTPUTRAWDATA 1

#define HAVE_MORE_CACHE_MAPPINGS 1
#define HAVE_MAXRUNS_TO_EVALUATE_HITS 1

typedef struct congruentaddrs {
	int wasaccessed;
	void *virtualaddrs[NR_OF_ADDRS];
} congruentaddrs_t;

typedef struct cache {
	congruentaddrs_t *congaddrs;
	void *cachebasepointer1;
#if HAVE_MORE_CACHE_MAPPINGS == 1
	void *cachebasepointer2;
	void *cachebasepointer3;
#endif
	int mappedsize;
	int pagemap;
	int numberofsets;
	int numberofways;
	int bitsofoffset;
	unsigned short int *analysis;
} cache_t;

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
	unsigned int *hit_counts;
	unsigned int *miss_counts;
} evictiondata_t;

typedef struct datacsvfile {
	cache_t llcache;
} datacsvfile_t;

void preparecache(cache_t **llcache, int mappedsize, int numberofsets, int numberofways,
		int bitsofoffset) {
	int i;

	*llcache = calloc(1, sizeof(cache_t));

	(*llcache)->mappedsize = mappedsize;
	(*llcache)->numberofsets = numberofsets;
	(*llcache)->numberofways = numberofways;
	(*llcache)->bitsofoffset = bitsofoffset;
	// Map ll cache
	(*llcache)->cachebasepointer1 = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*llcache)->cachebasepointer1 == MAP_FAILED)
		handle_error("mmap cachebasepointer1");
#if HAVE_MORE_CACHE_MAPPINGS == 1
	(*llcache)->cachebasepointer2 = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*llcache)->cachebasepointer2 == MAP_FAILED)
		handle_error("mmap cachebasepointer2");
	(*llcache)->cachebasepointer3 = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*llcache)->cachebasepointer3 == MAP_FAILED)
		handle_error("mmap cachebasepointer3");
#endif
	// Get file pointer for /proc/<pid>/pagemap
	(*llcache)->pagemap = open("/proc/self/pagemap", O_RDONLY);

	// Init mapping
	for (i = 0; i < mappedsize; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) (*llcache)->cachebasepointer1) + i;
		aux[0] = i;
	}

	// Init congaddrs
	(*llcache)->congaddrs = calloc(numberofsets, sizeof(congruentaddrs_t));

	// Init analysis
	(*llcache)->analysis = calloc(MAX_TIMES_TO_CSV * numberofsets,
			sizeof(unsigned short int));
}

void disposecache(cache_t *cache) {
	if (cache->cachebasepointer1 != NULL) {
		munmap(cache->cachebasepointer1, cache->mappedsize);
	}

	cache->mappedsize = 0;
	cache->cachebasepointer1 = NULL;

	free(cache);
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

unsigned int getsetindex(void *physicaladdr, int numberofsets, int bitsoffset) {
	return (((unsigned int) physicaladdr) >> bitsoffset) % numberofsets;
}

// L1 D-Cache |Tag(20 bits)|Set(6 bits)|offset(6 bits) = |
void getphysicalcongruentaddrs(evictionconfig_t *config, cache_t *llcache,
		unsigned int set, void *physicaladdr_src) {
	unsigned int i, count_found, index_aux;
	void *virtualaddr_aux, *physicaladdr_aux;
	const int virtualaddrslimit = config->evictionsetsize
			+ config->congruentvirtualaddrs - 1;
	count_found = 0;

	// CACHE BASEPOINTER1 -> Search for virtual addrs with the same physical index as the source virtual addr
	for (i = 0; count_found != virtualaddrslimit && i < llcache->mappedsize;
			i += CACHE_LINE_NUMBER_OF_BYTES) {
		virtualaddr_aux = llcache->cachebasepointer1 + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux, llcache->pagemap);
		index_aux = getsetindex(physicaladdr_aux, llcache->numberofsets,
				llcache->bitsofoffset);

		if (set == index_aux && physicaladdr_src != physicaladdr_aux) {
			llcache->congaddrs[set].virtualaddrs[count_found++] =
					virtualaddr_aux;
		}
	}
#if HAVE_MORE_CACHE_MAPPINGS == 1
	// CACHE BASEPOINTER2 -> Search for virtual addrs with the same physical index as the source virtual addr
	for (i = 0; count_found != virtualaddrslimit && i < llcache->mappedsize;
			i += CACHE_LINE_NUMBER_OF_BYTES) {
		virtualaddr_aux = llcache->cachebasepointer2 + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux, llcache->pagemap);
		index_aux = getsetindex(physicaladdr_aux, llcache->numberofsets,
				llcache->bitsofoffset);

		if (set == index_aux && physicaladdr_src != physicaladdr_aux) {
			llcache->congaddrs[set].virtualaddrs[count_found++] =
					virtualaddr_aux;
		}
	}
	// CACHE BASEPOINTER3 -> Search for virtual addrs with the same physical index as the source virtual addr
	for (i = 0; count_found != virtualaddrslimit && i < llcache->mappedsize;
			i += CACHE_LINE_NUMBER_OF_BYTES) {
		virtualaddr_aux = llcache->cachebasepointer3 + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux, llcache->pagemap);
		index_aux = getsetindex(physicaladdr_aux, llcache->numberofsets,
				llcache->bitsofoffset);

		if (set == index_aux && physicaladdr_src != physicaladdr_aux) {
			llcache->congaddrs[set].virtualaddrs[count_found++] =
					virtualaddr_aux;
		}
	}
#endif
	if (count_found != virtualaddrslimit)
		handle_error("not enough congruent addresses");

	llcache->congaddrs[set].wasaccessed = 1;
}

unsigned int evict(evictionconfig_t *config, congruentaddrs_t *congaddrs) {

	int icounter, iaccesses, icongruentaccesses;
	unsigned int setcycles = 0;
	for (icounter = 0; icounter < config->evictionsetsize; ++icounter) {
		for (iaccesses = 0; iaccesses < config->sameeviction; ++iaccesses) {
			for (icongruentaccesses = 0;
					icongruentaccesses < config->congruentvirtualaddrs;
					++icongruentaccesses) {
				setcycles += timeaccessway(
						congaddrs->virtualaddrs[icounter + icongruentaccesses]);
			}
		}
	}
	return setcycles;
}

unsigned int prime(evictionconfig_t *config, cache_t *llcache, unsigned int set) {

	if (llcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, llcache, set, NULL);
	}

	return evict(config, &(llcache->congaddrs[set]));
}

void prime1set1way(evictionconfig_t *config, cache_t *cache, unsigned int set){

	if (cache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, cache, set, NULL);
	}

	cache->congaddrs->virtualaddrs[cache->numberofways/2];

}

unsigned int probe(evictionconfig_t *config, cache_t *llcache, unsigned int set) {

	//Begin measuring time
	unsigned int setcycles = 0;
	//TODO: change drop the start here?

	int i, addrcount = config->evictionsetsize + config->congruentvirtualaddrs
			- 1;

	if (llcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, llcache, set, (void *) NULL);
	}
	congruentaddrs_t congaddrs = llcache->congaddrs[set];

	setcycles = 0;

	for (i = addrcount - 1; i >= 0; --i) {
		setcycles += timeaccessway(congaddrs.virtualaddrs[i]);
	}

	// Obtain operations time
	return setcycles;
}

void obtainevictiondata(int mappedsize, int evictionsetsize, int sameeviction,
		int congruentvirtualaddrs, int histogramsize, int histogramscale,
		int maxruns, evictiondata_t *evictiondata, cache_t *llcache, cache_t *testcache,
		evictionconfig_t *config) {
	unsigned int hits, misses;
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

	physicaladdr = getphysicaladdr(array + MID_ARRAY, llcache->pagemap);
	unsigned int set = getsetindex(physicaladdr, llcache->numberofsets,
			llcache->bitsofoffset);

	// Preparing for the hit histogram
	prime1set1way(config,testcache,set);

	// Hit histogram
	for (i = 0; i < maxruns; ++i) {
		prime(config, llcache, set);
		unsigned long probetime = probe(config, llcache, set) / histogramscale;
		evictiondata->hit_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Preparing for the miss histogram
	prime(config, llcache, set);

	// Miss histogram
	for (i = 0; i < maxruns; ++i) {
		prime(config, llcache, set);

		prime1set1way(config,testcache,set);

		unsigned long probetime = probe(config, llcache, set) / histogramscale;
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
		printf("%3d: %10zu %10zu\n", i * histogramscale,
				evictiondata->hit_counts[i], evictiondata->miss_counts[i]);
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

void analysellc(int set, cache_t *llcache, evictionconfig_t *config,
		int maxruns) {
	int i;

	for (i = set; i < maxruns; i += llcache->numberofsets) {

		//Prime
		prime(config, llcache, set);

		//Probe
		llcache->analysis[i] = probe(config, llcache, set);
	}
}

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

void analysehitandmissvariation(int numberofsets, int numberofways,
		char *filename, int analysissize, int evictionsetsize, int sameeviction,
		int congruentvirtualaddrs, int histogramsize, int histogramscale) {
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	int mappedsize;
	// Paper Cache-access pattern attack on disaligned AES t-tables
	// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
	const int NUMBER_TIMES_FOR_THE_TOTAL_EVICION = 5;
	mappedsize = (numberofsets * numberofways * CACHE_LINE_NUMBER_OF_BYTES)
			* NUMBER_TIMES_FOR_THE_TOTAL_EVICION;

	const int headerssize = 2;
	int i;
	unsigned int analysis_array[analysissize][headerssize];

	cache_t *llcache, *testcache;
	evictionconfig_t *config;

	preparecache(&llcache, mappedsize, numberofsets,numberofways,
	CACHE_NR_OF_BITS_OF_OFFSET);
	preparecache(&testcache, mappedsize, numberofsets,numberofways,
		CACHE_NR_OF_BITS_OF_OFFSET);
	prepareevictconfig(&config, evictionsetsize, sameeviction,
			congruentvirtualaddrs);

	for (i = 0; i < analysissize; ++i) {
//Test sucessive Prime VS Prime+Probe
//		graphprimes(mappedsize, evictionsetsize, sameeviction,
//						congruentvirtualaddrs, /*Histogram size*/histogramsize, /*Histogram scale*/
//						histogramscale,
//						MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, llcache, config);
		obtainevictiondata(mappedsize, evictionsetsize, sameeviction,
				congruentvirtualaddrs, /*Histogram size*/histogramsize, /*Histogram scale*/
				histogramscale,
				MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, llcache, testcache, config);
		analysis_array[i][0] = evictiondata->maxhit;
		analysis_array[i][1] = evictiondata->maxmiss;
	}
	const char *headers[headerssize];
	headers[0] = "Hits";
	headers[1] = "Misses";
	biarraytocsvwithstrheaders(filename, headers, analysissize, headerssize,
			analysis_array);
	disposecache(llcache);
}

//[2]
//void hitevaluation(const int maxruns, int increment, int size, unsigned int means[], unsigned int points[][maxruns]) {
//	int meansidx, sameaccess, basepointeridx;
//	//unsigned long long *basepointer = calloc(size, sizeof(unsigned long long));
//
//	unsigned long long *basepointer = mmap(0, size * sizeof(unsigned long long), PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//
//	//Init to populate pages
////	for (i = 0; i < size; i += PAGES_SIZE) {
////		unsigned long long *aux = ((void *) basepointer) + i;
////		aux[0] = i;
////	}
//
//	printf("BEGIN...\n");
//
//	for (meansidx = 0, sameaccess = 0, basepointeridx = 0; basepointeridx < size; ++sameaccess) {
//
////		void *aux = ((void *) basepointer) + i;
////		unsigned long long start = getcurrenttsc();
////		aux[0];
////		auxanalysis = getcurrenttsc() - start < UINT_MAX? auxanalysis : UINT_MAX;
////		analysis[analysisidx] = auxanalysis;
//		unsigned int aux = timeaccessway(&basepointer[basepointeridx]);
//		means[meansidx] += aux;
//		//points[i][sameaccess] = aux;
//		if(sameaccess == maxruns-1){
//			//printf("Means idx:: %d \t Basepointer idx:: %d \n",meansidx, basepointeridx);
//			means[meansidx] = means[meansidx] / maxruns;
//			++meansidx;
//			basepointeridx += increment;
//			sameaccess = 0;
//		}
//	}
//
//	//Dispose array mmap
//	//munmap(basepointer, size);
//
//	printf("END...\n");
//}

int TWO_hitevaluation(int size, int maxruns, int increment, unsigned int *analysis, int startanalysisidx) {
	int i, j, analysisidx;
	char *basepointer = mmap(0, size, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	//Init to populate pages
	for (i = 0; i < size; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) basepointer) + i;
		aux[0] = i;
	}
#if HAVE_MAXRUNS_TO_EVALUATE_HITS == 0
	for (i = 0, analysisidx = startanalysisidx; i < size;
			i += increment*3, analysisidx += 3) {
		analysis[analysisidx] = timeaccessway(((void *) basepointer) + i);
		analysis[analysisidx+1] = timeaccessway(((void *) basepointer) + (i + increment));
		analysis[analysisidx+2] = timeaccessway(((void *) basepointer) + (i + (2*increment)));
	}
#endif

#if HAVE_MAXRUNS_TO_EVALUATE_HITS == 1
	for (i = 0, analysisidx = startanalysisidx; i < size;
			i += increment*3, analysisidx +=3) {

//		unsigned long long start = getcurrenttsc();
		for(j = 0; j < maxruns;++j){
//			accessway(((void *) basepointer) + i);
			analysis[analysisidx] += timeaccessway(((void *) basepointer) + i);
			analysis[analysisidx+1] += timeaccessway(((void *) basepointer) + (i + increment));
			analysis[analysisidx+2] += timeaccessway(((void *) basepointer) + (i + (2*increment)));
		}
//		analysis[analysisidx] = (getcurrenttsc() - start) / maxruns;
		analysis[analysisidx] /= maxruns;
		analysis[analysisidx+1] /= maxruns;
		analysis[analysisidx+2] /= maxruns;
	}
#endif
	return analysisidx;

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
	unsigned int ramsize = llcsize * 2;
	// Size of evaluation array(where the cycles will be stores)
	unsigned int evaluationsize = l1size + llcsize + ramsize;
	// Allocate evaluation array(where the cycles will be stores)
	unsigned int *evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// File name
	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_evaluation.data");

	int analysedsize = 0;
	int increment = 4096;
	int maxruns = 10000;

	// Obtain cycles for the L1C
	analysedsize = TWO_hitevaluation(l1size, maxruns, increment, evaluation, analysedsize);
	// Obtain cycles for the LLC
	analysedsize = TWO_hitevaluation(llcsize, maxruns, increment, evaluation, analysedsize);
	// Obtain cycles for the 2xLLC
	analysedsize = TWO_hitevaluation(ramsize, maxruns, increment, evaluation, analysedsize);

	// Generate the file to be used by gnuplot
	arraytocsv(dstfilename, increment, analysedsize, evaluation);
}

int hitevaluation(int increment, int maxruns, int size, unsigned int *analysis, int startanalysisidx) {
	int i, j, analysisidx;
	//unsigned long long *basepointer = calloc(size, sizeof(unsigned long long));
//	unsigned long long *basepointer = mmap(0, size, PROT_READ | PROT_WRITE,
//			MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char basepointer[size];
	memset(basepointer,0,size);

//	//Init to populate pages
	for (i = 0; i < size; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) basepointer) + i;
		aux[0] = i;
	}

	for (i = 0, analysisidx = startanalysisidx; i < size;
			i += increment, ++analysisidx) {
		void *aux = ((void *) basepointer) + i;
		//printf("%X\n",aux);
		for(j = 0; j < maxruns; ++j){
			analysis[analysisidx] += timeaccessway(aux);
		}
		analysis[analysisidx] /= maxruns;
	}

	//Dispose array mmap
	//munmap(basepointer, size);
	return analysisidx;
}

//Test L1,LLC and RAM cycles of hits
void evaluate_l1_llc_ram() {
	int maxruns = 100000;
	int increment = 1;

	unsigned int l1size = 6 * 64 * 64;
	unsigned int llcsize = 16 * 1024 * 64;
	unsigned int ramsize = llcsize * 2;
	unsigned int evaluationsize = l1size + llcsize + ramsize;

	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_evaluation.data");
	printf("BEGIN...\n");
	unsigned int *evaluation = calloc(evaluationsize, sizeof(unsigned int));//mmap(0, evaluationsize * sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	unsigned int **points = calloc(maxruns * (evaluationsize/increment), sizeof(unsigned int *));

	int analysedsize = 0;
	printf("L1\n");
	analysedsize = hitevaluation(increment,maxruns,l1size, evaluation, analysedsize);
	printf("LLC\n");
	analysedsize = hitevaluation(increment,maxruns,llcsize, evaluation, analysedsize);
	printf("2*LLC\n");
	analysedsize = hitevaluation(increment,maxruns,ramsize, evaluation, analysedsize);

	arraytocsv(dstfilename, /*increment*/1, analysedsize, evaluation);
	printf("END...\n");
}

//[1] Test L1,LLC and RAM cycles of hits
//[1] TODO: UNDO BEFORE TESTING THE COPY OF THE METHOD ABOVE
//void evaluate_l1_llc_ram() {
//	int maxruns = 10000;
//	int increment = 100;
//
//	unsigned int l1size = 6 * 64 * 64;
//	unsigned int llcsize = 16 * 1024 * 64;
//	unsigned int ramsize = llcsize * 2;
//	unsigned int evaluationsize = ramsize;
//
//	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
//			"l1_llc_ram_evaluation.data");
//	printf("BEGIN...\n");
//	unsigned int *evaluation = calloc(evaluationsize, sizeof(unsigned int));//mmap(0, evaluationsize * sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//	unsigned int **points = calloc(maxruns * (evaluationsize/increment), sizeof(unsigned int *));
//	int finalsize = hitevaluation(increment, maxruns, ramsize, evaluation);
//
//	arraytocsv(dstfilename, /*increment*/10, finalsize, evaluation);
//	printf("END...\n");
//}

void evaluate_with_prime_probe(char * filenameprefix, cache_t *cache,
		evictionconfig_t *config) {
	void *array, *physicaladdr;
	int i;
	unsigned int maxruns = 2000;
	unsigned int prime_analysis_array[maxruns];
	unsigned int probe_analysis_array[maxruns];
	const int MID_ARRAY = PAGES_SIZE / 2;
	char * dirwithprefix = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			filenameprefix);
	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (array == MAP_FAILED)
		handle_error("mmap");
	physicaladdr = getphysicaladdr(array + MID_ARRAY, cache->pagemap);
	unsigned int set = getsetindex(physicaladdr, cache->numberofsets,
			cache->bitsofoffset);

	//Generate "Prime+Probe" line to the L1
	for (i = 0; i < maxruns; ++i) {
		prime_analysis_array[i] = prime(config, cache, set);
		probe_analysis_array[i] = probe(config, cache, set);
	}

	char * dstfilename1 = concat(dirwithprefix,
			"_measuring_primes_prime_probe_evaluation.data");
	char * dstfilename2 = concat(dirwithprefix,
			"_measuring_probes_prime_probe_evaluation.data");
//	arraytocsv(dstfilename1, maxruns, prime_analysis_array);
	arraytocsv(dstfilename2, 1,maxruns, probe_analysis_array);

	//Generate "Prime+Access_arrayl1+Probe" line to the L1
	for (i = 0; i < maxruns; ++i) {
		prime_analysis_array[i] = prime(config, cache, set);
		accessway(array + MID_ARRAY);
		probe_analysis_array[i] = probe(config, cache, set);
	}
	dstfilename1 = concat(dirwithprefix,
			"_measuring_primes_prime_access_probe_evaluation.data");
	dstfilename2 = concat(dirwithprefix,
			"_measuring_probes_prime_access_probe_evaluation.data");
//	arraytocsv(dstfilename1, maxruns, prime_analysis_array);
	arraytocsv(dstfilename2, 1,maxruns, probe_analysis_array);
}

void deprecated_evaluate_l1_llc_ram_with_prime_probe() {
	cache_t *l1, *llc, *ram;
	evictionconfig_t *l1_config, *llc_config, *ram_config;

	//Prepare and Map level 1 cache struct
	int l1mappedsize = 64 * 6 * 64;
	preparecache(&l1, l1mappedsize, 64, 6, 6);
	prepareevictconfig(&l1_config, 6, 1, 1);

	//***Evaluate to the L1***
	evaluate_with_prime_probe("L1", l1, l1_config);
	disposecache(l1);

	//Prepare and Map last level cache struct
	int llcmappedsize = 1024 * 16 * 64;
	preparecache(&llc, llcmappedsize, 1024, 16, 6);
	prepareevictconfig(&llc_config, 16, 1, 1);

	//***Evaluate to the LLC***
	evaluate_with_prime_probe("LLC", llc, llc_config);
	disposecache(llc);

	//Prepare and Map ram struct
	int rammappedsize = llcmappedsize * 2;
	preparecache(&ram, rammappedsize, 1024, 16, 6);
	prepareevictconfig(&ram_config, 16, 1, 1);

	//***Prepare array to the RAM***
	evaluate_with_prime_probe("RAM", ram, ram_config);
	disposecache(ram);
}

int hitevaluation_prime_probe(int evictionsize, int sameaccesses,
		int differentaccesses, int numberofsets, int numberofways,
		int cachelinesize, int bitsofoffset, int timesmappedsize,
		unsigned int *analysis, int startanalysisidx) {
	int i, analysisidx;
	cache_t *cache;
	evictionconfig_t *config;
	int mappedsize = numberofsets * numberofways * cachelinesize
			* timesmappedsize;
	preparecache(&cache, mappedsize, numberofsets, numberofways,bitsofoffset);
	prepareevictconfig(&config, evictionsize, sameaccesses, differentaccesses);

//	int auxanalysis;
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			++i, ++analysisidx) {
		prime(config, cache, i);
		analysis[analysisidx] = probe(config, cache, i);
	}
	return analysisidx + 1;
}

int missevaluation_prime_probe(int evictionsize, int sameaccesses,
		int differentaccesses, int numberofsets, int numberofways,
		int cachelinesize, int bitsofoffset, int timesmappedsize,
		unsigned int *analysis, int startanalysisidx) {
	int i, analysisidx;
	cache_t *cache, *testvictim;
	evictionconfig_t *config;
	int mappedsize = numberofsets * numberofways * cachelinesize
			* timesmappedsize;
	preparecache(&cache, mappedsize, numberofsets, numberofways, bitsofoffset);
	preparecache(&testvictim, mappedsize, numberofsets, numberofways, bitsofoffset);

	prepareevictconfig(&config, evictionsize, sameaccesses, differentaccesses);

//	int auxanalysis;
	for (i = 0, analysisidx = startanalysisidx; i < numberofsets;
			++i, ++analysisidx) {
		//Prime cache set
		prime(config, cache, i);

		//VERYGOOD WITH ONE WAY
		prime1set1way(config, testvictim, i);

		//VERYGOOD BUT ALL WAYS
		//prime(config, testvictim, i);

		//Probe and measure cache set
		analysis[analysisidx] = probe(config, cache, i);
	}
	return analysisidx + 1;
}

typedef struct evaluationdata{
	unsigned int *evaluation;
	int analysedsize;
}evaluationdata_t;

evaluationdata_t * evaluate_l1_llc_ram_with_prime_probe(char *filename, int l1evictionsize,
		int l1sameaccesses, int l1differentaccesses, int llcevictionsize,
		int llcsameaccesses, int llcdifferentaccesses, int llc2evictionsize,
		int llc2sameaccesses, int llc2differentaccesses) {
	evaluationdata_t *evadata = calloc(1, sizeof(evaluationdata_t));
	int l1nrsets = 64;
	int l1nrways = 6;
	int bytescacheline = 64;
	int bitsofoffset = 6;
	int llcnrsets = 1024;
	int llcnrways = 16;
	unsigned int evaluationsize = l1nrsets + llcnrsets + llcnrsets * 2;
	evadata->evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	//const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
	//		filename);
	if(l1evictionsize != 0){
		printf("[+] L1\n");
		evadata->analysedsize = hitevaluation_prime_probe(l1evictionsize, l1sameaccesses,
				l1differentaccesses, l1nrsets, l1nrways, bytescacheline,
				bitsofoffset, 1, evadata->evaluation, evadata->analysedsize);
	}
	if(llcevictionsize != 0){
		printf("[+] LLC\n");
		evadata->analysedsize = hitevaluation_prime_probe(llcevictionsize, llcsameaccesses,
				llcdifferentaccesses, llcnrsets, llcnrways, bytescacheline,
				bitsofoffset, 1, evadata->evaluation, evadata->analysedsize);
	}
	if(llc2evictionsize != 0){
		printf("[+] 2*LLC\n");
		evadata->analysedsize = hitevaluation_prime_probe(llc2evictionsize,
				llc2sameaccesses, llc2differentaccesses, llcnrsets * 2,
				llcnrways * 2, bytescacheline, bitsofoffset, 1, evadata->evaluation,
				evadata->analysedsize);
	}

	//arraytocsv(dstfilename, analysedsize, evaluation);
	return evadata;
}

evaluationdata_t * evaluate_l1_llc_ram_with_prime_access_probe(char *filename, int l1evictionsize,
		int l1sameaccesses, int l1differentaccesses, int llcevictionsize,
		int llcsameaccesses, int llcdifferentaccesses, int llc2evictionsize,
		int llc2sameaccesses, int llc2differentaccesses) {
	evaluationdata_t *evadata = calloc(1, sizeof(evaluationdata_t));
	int l1nrsets = 64;
	int l1nrways = 6;
	int bytescacheline = 64;
	int bitsofoffset = 6;
	int llcnrsets = 1024;
	int llcnrways = 16;
	unsigned int evaluationsize = l1nrsets + llcnrsets + llcnrsets * 2;
	evadata->evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	//const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
	//		filename);
	if(l1evictionsize != 0){
		printf("[+] L1\n");
		evadata->analysedsize = missevaluation_prime_probe(l1evictionsize, l1sameaccesses,
				l1differentaccesses, l1nrsets, l1nrways, bytescacheline,
				bitsofoffset, 1, evadata->evaluation, evadata->analysedsize);
	}
	if(llcevictionsize != 0){
		printf("[+] LLC\n");
		evadata->analysedsize = missevaluation_prime_probe(llcevictionsize, llcsameaccesses,
				llcdifferentaccesses, llcnrsets, llcnrways, bytescacheline,
				bitsofoffset, 1, evadata->evaluation, evadata->analysedsize);
	}
	if(llc2evictionsize != 0){
		printf("[+] 2*LLC\n");
		evadata->analysedsize = missevaluation_prime_probe(llc2evictionsize,
				llc2sameaccesses, llc2differentaccesses, llcnrsets * 2,
				llcnrways * 2, bytescacheline, bitsofoffset, 1, evadata->evaluation,
				evadata->analysedsize);
	}
	//arraytocsv(dstfilename, analysedsize, evaluation);
	return evadata;
}

void generatehistogram(char *prefix, int numberofsets, int numberofways,
		int waysize, int timesmappedsize, int bitsofoffset, int evictionsetsize,
		int sameeviction, int differentaddrs, int histogramscale,
		int histogramsize) {
	cache_t *cache, *testvictim;
	evictionconfig_t *config;
	int mappedsize = numberofsets * numberofways * waysize * timesmappedsize;
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));

	preparecache(&cache, mappedsize, numberofsets, numberofways, bitsofoffset);
	prepareevictconfig(&config, evictionsetsize, sameeviction, differentaddrs);
	preparecache(&testvictim, mappedsize, numberofsets, numberofways, bitsofoffset);

	obtainevictiondata(mappedsize, evictionsetsize, sameeviction,
			differentaddrs, histogramsize, histogramscale,
			/*maxruns*/MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, cache, testvictim,
			config);

	char *dirwithprefix = concat(VARIATION_ANALYSIS_DATA_DIRECTORY, prefix);
	char *dstfilename = concat(dirwithprefix, "_prime_probe_histogram.data");
	twoarraystocsvwithstrheaders(dstfilename, "Prime+Probe(Hit)",
			"Prime+Access+Probe(Miss)", histogramscale, histogramsize,
			evictiondata->hit_counts, evictiondata->miss_counts);
	disposecache(cache);
}

int main() {

	setcoreaffinity(0);

	TWO_evaluate_l1_llc_ram();

	//[+]BEGIN Obtain unified graphs L1 Prime+Probe | Prime+Access+Probe
//	char *dstfilename;
//	evaluationdata_t *evadata1 = calloc(1,sizeof(evaluationdata_t));
//	evaluationdata_t *evadata2 = calloc(1,sizeof(evaluationdata_t));
//
//	printf("%s","Begin evaluation... L1 Prime+Probe\n");
//	evadata1 = evaluate_l1_llc_ram_with_prime_probe("l1_14_2_2_prime+probe_evaluation.data",/*L1*/14, 2, 2, /*LLC*/0, 1, 1, /*2LLC*/0, 1, 1);
//	printf("%s","End evaluation...\n");
//	printf("%s","Begin evaluation... L1 Prime+Access+Probe\n");
//	evadata2 = evaluate_l1_llc_ram_with_prime_access_probe("l1_14_2_2_prime+access+probe_evaluation.data",/*L1*/14, 2, 2, /*LLC*/0, 1, 1, /*2LLC*/0, 1, 1);
//	printf("%s","End evaluation...\n");
//
//	dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY, "l1_14_2_2_prime+probe_evaluation.data");
//	twoarraystocsvwithstrheaders(dstfilename, "Prime+Probe(Hit)",
//			"Prime+Access+Probe(Miss)", 1, evadata1->analysedsize,
//			evadata1->evaluation, evadata2->evaluation);
	//[+]END Obtain unified graphs L1 Prime+Probe | Prime+Access+Probe

//	printf("%s","Begin evaluation... Prime+Probe\n");
//	evaluate_l1_llc_ram_with_prime_probe("l1_llc_2llc_prime+probe_evaluation.data",/*L1*/6, 1, 1, /*LLC*/16, 1, 1, /*2LLC*/32, 1, 1);
//	printf("%s","End evaluation...\n");
//	printf("%s","Begin evaluation... Prime+Access+Probe\n");
//	evaluate_l1_llc_ram_with_prime_access_probe("l1_llc_2llc_prime+access+probe_evaluation.data",/*L1*/6, 1, 1, /*LLC*/16, 1, 1, /*2LLC*/32, 1, 1);
//	printf("%s","End evaluation...\n");

//	const int histogramsize = 10000;
//	const int histogramscale = 5;
////Uncomment
//	const int evictionsetsize = 16;
//	const int sameeviction = 16;
//	const int differentvirtualaddrs = 16;
//	const int analysissize = 10;
//
//	int i;
//	for(i = 16; i < 33; i+=16){
//		char filename[200]="";
//		sprintf(filename, "%s%d_%d_%d_%s\0",VARIATION_ANALYSIS_DATA_DIRECTORY,16,8,1,VARIATION_ANALYSIS_DATA_FILENAME);
//		analysehitandmissvariation(filename,analysissize, 16, 8,
//				1, histogramsize, histogramscale);

//	}
//	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
//	int mappedsize;
//// Paper Cache-access pattern attack on disaligned AES t-tables
//// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
//	const int NUMBER_TIMES_FOR_THE_TOTAL_EVICION = 5;
//	mappedsize = (LL_CACHE_NUMBER_OF_SETS * LL_CACHE_NUMBER_OF_WAYS
//			* LL_CACHE_LINE_NUMBER_OF_BYTES)
//			* NUMBER_TIMES_FOR_THE_TOTAL_EVICION;
//
//	llcache_t *llcache;
//	evictionconfig_t *config;
//
//	preparellcache(&llcache, mappedsize);
////Uncomment
////	prepareevictconfig(&config, evictionsetsize, sameeviction,
////			differentvirtualaddrs);
//
//	int eviction=23,diff=5,same=2;
//	//for(eviction = 30;eviction < 50;eviction += 1){
//		//for(same = 1;same < 60;same += 5){
//			//for(diff = 2;diff < 4;diff += 2){
//				prepareevictconfig(&config, eviction, same,diff);
//				// Init congaddrs
//				memset(llcache->congaddrs, 0, LL_CACHE_NUMBER_OF_SETS * sizeof(congruentaddrs_t));
//				obtainevictiondata(mappedsize,eviction /*evictionsetsize*/, same /*sameeviction*/,
//						diff /*differentvirtualaddrs*/, /*Histogram size*/histogramsize, /*Histogram scale*/
//						histogramscale,
//						MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, llcache, config);
//				if (evictiondata->evictionrate > 50) {
//					printf("Eviction NR: %d. Same NR: %d. Different NR: %d.\n", eviction,same,diff);
//					if (evictiondata->maxhit >= evictiondata->maxmiss) {
//						printf("[!] Cycles of Hit >= Cycles of Miss [!]\n");
//					}
//		//Uncomment
//		//			printf("Max Hit: %u\n", evictiondata->maxhit);
//		//			printf("Max Miss: %u\n", evictiondata->maxmiss);
//		//			printf("Threshold: %u\n", evictiondata->threshold);
//		//			printf("Hits Rate: %lf\%\n", evictiondata->hitsrate);
//					printf("Eviction Rate: %lf\%\n", evictiondata->evictionrate);
//				}
//			//}
//		//}
//	//}
////Uncomment
////	waitforvictim_t *waitforvictim;
////	int setidx;
////
////	preparellcache(&llcache, mappedsize);
////	prepareevictconfig(&config, evictionsetsize, sameeviction,
////			differentvirtualaddrs);
////	preparewaitforactivity(&waitforvictim);
////	for (setidx = 0; setidx < DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/; ++setidx) {
////		printf("\nWaiting for activity...\n");
////
////		waitforvictimactivity(waitforvictim);
////
////		//int setidx = 1;
////		printf("Analyse set number: %d\n", setidx);
////		analysellc(setidx, llcache, config,
////		MAX_TIMES_TO_CSV * DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/);
////	}
////
////	arraytodatafilewithoutlabels(PROBE_ANALYSIS_DATA_FILENAME,
////			llcache->llc_analysis,
////			MAX_TIMES_TO_CSV, DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/);

//	generatehistogram("LLC", /*numberofsets*/1024,
//			/*numberofways*/16, /*waysize*/64, /*timesmappedsize*/3, /*bitsofoffset*/6, /*evictionsetsize*/30,
//			/*sameeviction*/1, /*differentaddrs*/1, /*histogramscale*/5, /*histogramsize*/1000);
//	generatehistogram("L1", /*numberofsets*/64,
//	/*numberofways*/6, /*waysize*/64, /*timesmappedsize*/1,/*bitsofoffset*/6, /*evictionsetsize*/
//	14,
//	/*sameeviction*/2, /*differentaddrs*/2, /*histogramscale*/5, /*histogramsize*/
//	300);

	return 0;
}




