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


int antes_de_email_19_06_2017_TWO_hitevaluation(int size, int maxruns, int increment, unsigned int *analysis, int startanalysisidx) {
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

#define LOOPUNROLLING 1

int depois_de_email_19_06_2017_TWO_hitevaluation(int size, int maxruns, int increment, int sizetoanalyze, unsigned int *analysis, int startanalysisidx) {
	int i, j, analysisidx = 0;
	char *basepointer = mmap(0, size, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	//Init to populate pages
	for (i = 0; i < size; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) basepointer) + i;
		aux[0] = i;
	}

	//CREATE NEW DEFINE
#if LOOPUNROLLING == 0
	unsigned int averageaccestime = 0, idxanalyzed = 0;
	unsigned long long start;
	for(idxanalyzed = startanalysisidx; idxanalyzed < sizetoanalyze; ++idxanalyzed) {
		start = getcurrenttsc();
		for(j = 0; j < maxruns;++j){
			for (i = 0; i < size; i += increment) {
				accessway(((void *) basepointer) + i);
				if(j==0)
					printf("accessway(((void *) basepointer) + %d);\n",i);
			}
		}
		averageaccestime = (getcurrenttsc() - start) / (maxruns*(size/increment));
		//printf("Cache with size: %d | Average Time: %d\n",size,averageaccestime);
		analysis[idxanalyzed] = averageaccestime;
	}
#endif

#if LOOPUNROLLING == 1
	unsigned int averageaccestime = 0, idxanalyzed = 0;
	unsigned long long start;
	for( idxanalyzed = startanalysisidx; idxanalyzed < sizetoanalyze; ++idxanalyzed) {
		printf( "Idxanalyzed: %d\n", idxanalyzed);
		start = getcurrenttsc();
		for(j = 0; j < maxruns;++j){
			accessway(((void *) basepointer) + 0);
			accessway(((void *) basepointer) + 4096);
			accessway(((void *) basepointer) + 8192);
			accessway(((void *) basepointer) + 12288);
			accessway(((void *) basepointer) + 16384);
			accessway(((void *) basepointer) + 20480);
			if(size > 1044480){
				accessway(((void *) basepointer) + 24576);
				accessway(((void *) basepointer) + 28672);
				accessway(((void *) basepointer) + 32768);
				accessway(((void *) basepointer) + 36864);
				accessway(((void *) basepointer) + 40960);
				accessway(((void *) basepointer) + 45056);
				accessway(((void *) basepointer) + 49152);
				accessway(((void *) basepointer) + 53248);
				accessway(((void *) basepointer) + 57344);
				accessway(((void *) basepointer) + 61440);
				accessway(((void *) basepointer) + 65536);
				accessway(((void *) basepointer) + 69632);
				accessway(((void *) basepointer) + 73728);
				accessway(((void *) basepointer) + 77824);
				accessway(((void *) basepointer) + 81920);
				accessway(((void *) basepointer) + 86016);
				accessway(((void *) basepointer) + 90112);
				accessway(((void *) basepointer) + 94208);
				accessway(((void *) basepointer) + 98304);
				accessway(((void *) basepointer) + 102400);
				accessway(((void *) basepointer) + 106496);
				accessway(((void *) basepointer) + 110592);
				accessway(((void *) basepointer) + 114688);
				accessway(((void *) basepointer) + 118784);
				accessway(((void *) basepointer) + 122880);
				accessway(((void *) basepointer) + 126976);
				accessway(((void *) basepointer) + 131072);
				accessway(((void *) basepointer) + 135168);
				accessway(((void *) basepointer) + 139264);
				accessway(((void *) basepointer) + 143360);
				accessway(((void *) basepointer) + 147456);
				accessway(((void *) basepointer) + 151552);
				accessway(((void *) basepointer) + 155648);
				accessway(((void *) basepointer) + 159744);
				accessway(((void *) basepointer) + 163840);
				accessway(((void *) basepointer) + 167936);
				accessway(((void *) basepointer) + 172032);
				accessway(((void *) basepointer) + 176128);
				accessway(((void *) basepointer) + 180224);
				accessway(((void *) basepointer) + 184320);
				accessway(((void *) basepointer) + 188416);
				accessway(((void *) basepointer) + 192512);
				accessway(((void *) basepointer) + 196608);
				accessway(((void *) basepointer) + 200704);
				accessway(((void *) basepointer) + 204800);
				accessway(((void *) basepointer) + 208896);
				accessway(((void *) basepointer) + 212992);
				accessway(((void *) basepointer) + 217088);
				accessway(((void *) basepointer) + 221184);
				accessway(((void *) basepointer) + 225280);
				accessway(((void *) basepointer) + 229376);
				accessway(((void *) basepointer) + 233472);
				accessway(((void *) basepointer) + 237568);
				accessway(((void *) basepointer) + 241664);
				accessway(((void *) basepointer) + 245760);
				accessway(((void *) basepointer) + 249856);
				accessway(((void *) basepointer) + 253952);
				accessway(((void *) basepointer) + 258048);
				accessway(((void *) basepointer) + 262144);
				accessway(((void *) basepointer) + 266240);
				accessway(((void *) basepointer) + 270336);
				accessway(((void *) basepointer) + 274432);
				accessway(((void *) basepointer) + 278528);
				accessway(((void *) basepointer) + 282624);
				accessway(((void *) basepointer) + 286720);
				accessway(((void *) basepointer) + 290816);
				accessway(((void *) basepointer) + 294912);
				accessway(((void *) basepointer) + 299008);
				accessway(((void *) basepointer) + 303104);
				accessway(((void *) basepointer) + 307200);
				accessway(((void *) basepointer) + 311296);
				accessway(((void *) basepointer) + 315392);
				accessway(((void *) basepointer) + 319488);
				accessway(((void *) basepointer) + 323584);
				accessway(((void *) basepointer) + 327680);
				accessway(((void *) basepointer) + 331776);
				accessway(((void *) basepointer) + 335872);
				accessway(((void *) basepointer) + 339968);
				accessway(((void *) basepointer) + 344064);
				accessway(((void *) basepointer) + 348160);
				accessway(((void *) basepointer) + 352256);
				accessway(((void *) basepointer) + 356352);
				accessway(((void *) basepointer) + 360448);
				accessway(((void *) basepointer) + 364544);
				accessway(((void *) basepointer) + 368640);
				accessway(((void *) basepointer) + 372736);
				accessway(((void *) basepointer) + 376832);
				accessway(((void *) basepointer) + 380928);
				accessway(((void *) basepointer) + 385024);
				accessway(((void *) basepointer) + 389120);
				accessway(((void *) basepointer) + 393216);
				accessway(((void *) basepointer) + 397312);
				accessway(((void *) basepointer) + 401408);
				accessway(((void *) basepointer) + 405504);
				accessway(((void *) basepointer) + 409600);
				accessway(((void *) basepointer) + 413696);
				accessway(((void *) basepointer) + 417792);
				accessway(((void *) basepointer) + 421888);
				accessway(((void *) basepointer) + 425984);
				accessway(((void *) basepointer) + 430080);
				accessway(((void *) basepointer) + 434176);
				accessway(((void *) basepointer) + 438272);
				accessway(((void *) basepointer) + 442368);
				accessway(((void *) basepointer) + 446464);
				accessway(((void *) basepointer) + 450560);
				accessway(((void *) basepointer) + 454656);
				accessway(((void *) basepointer) + 458752);
				accessway(((void *) basepointer) + 462848);
				accessway(((void *) basepointer) + 466944);
				accessway(((void *) basepointer) + 471040);
				accessway(((void *) basepointer) + 475136);
				accessway(((void *) basepointer) + 479232);
				accessway(((void *) basepointer) + 483328);
				accessway(((void *) basepointer) + 487424);
				accessway(((void *) basepointer) + 491520);
				accessway(((void *) basepointer) + 495616);
				accessway(((void *) basepointer) + 499712);
				accessway(((void *) basepointer) + 503808);
				accessway(((void *) basepointer) + 507904);
				accessway(((void *) basepointer) + 512000);
				accessway(((void *) basepointer) + 516096);
				accessway(((void *) basepointer) + 520192);
				accessway(((void *) basepointer) + 524288);
				accessway(((void *) basepointer) + 528384);
				accessway(((void *) basepointer) + 532480);
				accessway(((void *) basepointer) + 536576);
				accessway(((void *) basepointer) + 540672);
				accessway(((void *) basepointer) + 544768);
				accessway(((void *) basepointer) + 548864);
				accessway(((void *) basepointer) + 552960);
				accessway(((void *) basepointer) + 557056);
				accessway(((void *) basepointer) + 561152);
				accessway(((void *) basepointer) + 565248);
				accessway(((void *) basepointer) + 569344);
				accessway(((void *) basepointer) + 573440);
				accessway(((void *) basepointer) + 577536);
				accessway(((void *) basepointer) + 581632);
				accessway(((void *) basepointer) + 585728);
				accessway(((void *) basepointer) + 589824);
				accessway(((void *) basepointer) + 593920);
				accessway(((void *) basepointer) + 598016);
				accessway(((void *) basepointer) + 602112);
				accessway(((void *) basepointer) + 606208);
				accessway(((void *) basepointer) + 610304);
				accessway(((void *) basepointer) + 614400);
				accessway(((void *) basepointer) + 618496);
				accessway(((void *) basepointer) + 622592);
				accessway(((void *) basepointer) + 626688);
				accessway(((void *) basepointer) + 630784);
				accessway(((void *) basepointer) + 634880);
				accessway(((void *) basepointer) + 638976);
				accessway(((void *) basepointer) + 643072);
				accessway(((void *) basepointer) + 647168);
				accessway(((void *) basepointer) + 651264);
				accessway(((void *) basepointer) + 655360);
				accessway(((void *) basepointer) + 659456);
				accessway(((void *) basepointer) + 663552);
				accessway(((void *) basepointer) + 667648);
				accessway(((void *) basepointer) + 671744);
				accessway(((void *) basepointer) + 675840);
				accessway(((void *) basepointer) + 679936);
				accessway(((void *) basepointer) + 684032);
				accessway(((void *) basepointer) + 688128);
				accessway(((void *) basepointer) + 692224);
				accessway(((void *) basepointer) + 696320);
				accessway(((void *) basepointer) + 700416);
				accessway(((void *) basepointer) + 704512);
				accessway(((void *) basepointer) + 708608);
				accessway(((void *) basepointer) + 712704);
				accessway(((void *) basepointer) + 716800);
				accessway(((void *) basepointer) + 720896);
				accessway(((void *) basepointer) + 724992);
				accessway(((void *) basepointer) + 729088);
				accessway(((void *) basepointer) + 733184);
				accessway(((void *) basepointer) + 737280);
				accessway(((void *) basepointer) + 741376);
				accessway(((void *) basepointer) + 745472);
				accessway(((void *) basepointer) + 749568);
				accessway(((void *) basepointer) + 753664);
				accessway(((void *) basepointer) + 757760);
				accessway(((void *) basepointer) + 761856);
				accessway(((void *) basepointer) + 765952);
				accessway(((void *) basepointer) + 770048);
				accessway(((void *) basepointer) + 774144);
				accessway(((void *) basepointer) + 778240);
				accessway(((void *) basepointer) + 782336);
				accessway(((void *) basepointer) + 786432);
				accessway(((void *) basepointer) + 790528);
				accessway(((void *) basepointer) + 794624);
				accessway(((void *) basepointer) + 798720);
				accessway(((void *) basepointer) + 802816);
				accessway(((void *) basepointer) + 806912);
				accessway(((void *) basepointer) + 811008);
				accessway(((void *) basepointer) + 815104);
				accessway(((void *) basepointer) + 819200);
				accessway(((void *) basepointer) + 823296);
				accessway(((void *) basepointer) + 827392);
				accessway(((void *) basepointer) + 831488);
				accessway(((void *) basepointer) + 835584);
				accessway(((void *) basepointer) + 839680);
				accessway(((void *) basepointer) + 843776);
				accessway(((void *) basepointer) + 847872);
				accessway(((void *) basepointer) + 851968);
				accessway(((void *) basepointer) + 856064);
				accessway(((void *) basepointer) + 860160);
				accessway(((void *) basepointer) + 864256);
				accessway(((void *) basepointer) + 868352);
				accessway(((void *) basepointer) + 872448);
				accessway(((void *) basepointer) + 876544);
				accessway(((void *) basepointer) + 880640);
				accessway(((void *) basepointer) + 884736);
				accessway(((void *) basepointer) + 888832);
				accessway(((void *) basepointer) + 892928);
				accessway(((void *) basepointer) + 897024);
				accessway(((void *) basepointer) + 901120);
				accessway(((void *) basepointer) + 905216);
				accessway(((void *) basepointer) + 909312);
				accessway(((void *) basepointer) + 913408);
				accessway(((void *) basepointer) + 917504);
				accessway(((void *) basepointer) + 921600);
				accessway(((void *) basepointer) + 925696);
				accessway(((void *) basepointer) + 929792);
				accessway(((void *) basepointer) + 933888);
				accessway(((void *) basepointer) + 937984);
				accessway(((void *) basepointer) + 942080);
				accessway(((void *) basepointer) + 946176);
				accessway(((void *) basepointer) + 950272);
				accessway(((void *) basepointer) + 954368);
				accessway(((void *) basepointer) + 958464);
				accessway(((void *) basepointer) + 962560);
				accessway(((void *) basepointer) + 966656);
				accessway(((void *) basepointer) + 970752);
				accessway(((void *) basepointer) + 974848);
				accessway(((void *) basepointer) + 978944);
				accessway(((void *) basepointer) + 983040);
				accessway(((void *) basepointer) + 987136);
				accessway(((void *) basepointer) + 991232);
				accessway(((void *) basepointer) + 995328);
				accessway(((void *) basepointer) + 999424);
				accessway(((void *) basepointer) + 1003520);
				accessway(((void *) basepointer) + 1007616);
				accessway(((void *) basepointer) + 1011712);
				accessway(((void *) basepointer) + 1015808);
				accessway(((void *) basepointer) + 1019904);
				accessway(((void *) basepointer) + 1024000);
				accessway(((void *) basepointer) + 1028096);
				accessway(((void *) basepointer) + 1032192);
				accessway(((void *) basepointer) + 1036288);
				accessway(((void *) basepointer) + 1040384);
				accessway(((void *) basepointer) + 1044480);
				if(size > 2093056){
					accessway(((void *) basepointer) + 1048576);
					accessway(((void *) basepointer) + 1052672);
					accessway(((void *) basepointer) + 1056768);
					accessway(((void *) basepointer) + 1060864);
					accessway(((void *) basepointer) + 1064960);
					accessway(((void *) basepointer) + 1069056);
					accessway(((void *) basepointer) + 1073152);
					accessway(((void *) basepointer) + 1077248);
					accessway(((void *) basepointer) + 1081344);
					accessway(((void *) basepointer) + 1085440);
					accessway(((void *) basepointer) + 1089536);
					accessway(((void *) basepointer) + 1093632);
					accessway(((void *) basepointer) + 1097728);
					accessway(((void *) basepointer) + 1101824);
					accessway(((void *) basepointer) + 1105920);
					accessway(((void *) basepointer) + 1110016);
					accessway(((void *) basepointer) + 1114112);
					accessway(((void *) basepointer) + 1118208);
					accessway(((void *) basepointer) + 1122304);
					accessway(((void *) basepointer) + 1126400);
					accessway(((void *) basepointer) + 1130496);
					accessway(((void *) basepointer) + 1134592);
					accessway(((void *) basepointer) + 1138688);
					accessway(((void *) basepointer) + 1142784);
					accessway(((void *) basepointer) + 1146880);
					accessway(((void *) basepointer) + 1150976);
					accessway(((void *) basepointer) + 1155072);
					accessway(((void *) basepointer) + 1159168);
					accessway(((void *) basepointer) + 1163264);
					accessway(((void *) basepointer) + 1167360);
					accessway(((void *) basepointer) + 1171456);
					accessway(((void *) basepointer) + 1175552);
					accessway(((void *) basepointer) + 1179648);
					accessway(((void *) basepointer) + 1183744);
					accessway(((void *) basepointer) + 1187840);
					accessway(((void *) basepointer) + 1191936);
					accessway(((void *) basepointer) + 1196032);
					accessway(((void *) basepointer) + 1200128);
					accessway(((void *) basepointer) + 1204224);
					accessway(((void *) basepointer) + 1208320);
					accessway(((void *) basepointer) + 1212416);
					accessway(((void *) basepointer) + 1216512);
					accessway(((void *) basepointer) + 1220608);
					accessway(((void *) basepointer) + 1224704);
					accessway(((void *) basepointer) + 1228800);
					accessway(((void *) basepointer) + 1232896);
					accessway(((void *) basepointer) + 1236992);
					accessway(((void *) basepointer) + 1241088);
					accessway(((void *) basepointer) + 1245184);
					accessway(((void *) basepointer) + 1249280);
					accessway(((void *) basepointer) + 1253376);
					accessway(((void *) basepointer) + 1257472);
					accessway(((void *) basepointer) + 1261568);
					accessway(((void *) basepointer) + 1265664);
					accessway(((void *) basepointer) + 1269760);
					accessway(((void *) basepointer) + 1273856);
					accessway(((void *) basepointer) + 1277952);
					accessway(((void *) basepointer) + 1282048);
					accessway(((void *) basepointer) + 1286144);
					accessway(((void *) basepointer) + 1290240);
					accessway(((void *) basepointer) + 1294336);
					accessway(((void *) basepointer) + 1298432);
					accessway(((void *) basepointer) + 1302528);
					accessway(((void *) basepointer) + 1306624);
					accessway(((void *) basepointer) + 1310720);
					accessway(((void *) basepointer) + 1314816);
					accessway(((void *) basepointer) + 1318912);
					accessway(((void *) basepointer) + 1323008);
					accessway(((void *) basepointer) + 1327104);
					accessway(((void *) basepointer) + 1331200);
					accessway(((void *) basepointer) + 1335296);
					accessway(((void *) basepointer) + 1339392);
					accessway(((void *) basepointer) + 1343488);
					accessway(((void *) basepointer) + 1347584);
					accessway(((void *) basepointer) + 1351680);
					accessway(((void *) basepointer) + 1355776);
					accessway(((void *) basepointer) + 1359872);
					accessway(((void *) basepointer) + 1363968);
					accessway(((void *) basepointer) + 1368064);
					accessway(((void *) basepointer) + 1372160);
					accessway(((void *) basepointer) + 1376256);
					accessway(((void *) basepointer) + 1380352);
					accessway(((void *) basepointer) + 1384448);
					accessway(((void *) basepointer) + 1388544);
					accessway(((void *) basepointer) + 1392640);
					accessway(((void *) basepointer) + 1396736);
					accessway(((void *) basepointer) + 1400832);
					accessway(((void *) basepointer) + 1404928);
					accessway(((void *) basepointer) + 1409024);
					accessway(((void *) basepointer) + 1413120);
					accessway(((void *) basepointer) + 1417216);
					accessway(((void *) basepointer) + 1421312);
					accessway(((void *) basepointer) + 1425408);
					accessway(((void *) basepointer) + 1429504);
					accessway(((void *) basepointer) + 1433600);
					accessway(((void *) basepointer) + 1437696);
					accessway(((void *) basepointer) + 1441792);
					accessway(((void *) basepointer) + 1445888);
					accessway(((void *) basepointer) + 1449984);
					accessway(((void *) basepointer) + 1454080);
					accessway(((void *) basepointer) + 1458176);
					accessway(((void *) basepointer) + 1462272);
					accessway(((void *) basepointer) + 1466368);
					accessway(((void *) basepointer) + 1470464);
					accessway(((void *) basepointer) + 1474560);
					accessway(((void *) basepointer) + 1478656);
					accessway(((void *) basepointer) + 1482752);
					accessway(((void *) basepointer) + 1486848);
					accessway(((void *) basepointer) + 1490944);
					accessway(((void *) basepointer) + 1495040);
					accessway(((void *) basepointer) + 1499136);
					accessway(((void *) basepointer) + 1503232);
					accessway(((void *) basepointer) + 1507328);
					accessway(((void *) basepointer) + 1511424);
					accessway(((void *) basepointer) + 1515520);
					accessway(((void *) basepointer) + 1519616);
					accessway(((void *) basepointer) + 1523712);
					accessway(((void *) basepointer) + 1527808);
					accessway(((void *) basepointer) + 1531904);
					accessway(((void *) basepointer) + 1536000);
					accessway(((void *) basepointer) + 1540096);
					accessway(((void *) basepointer) + 1544192);
					accessway(((void *) basepointer) + 1548288);
					accessway(((void *) basepointer) + 1552384);
					accessway(((void *) basepointer) + 1556480);
					accessway(((void *) basepointer) + 1560576);
					accessway(((void *) basepointer) + 1564672);
					accessway(((void *) basepointer) + 1568768);
					accessway(((void *) basepointer) + 1572864);
					accessway(((void *) basepointer) + 1576960);
					accessway(((void *) basepointer) + 1581056);
					accessway(((void *) basepointer) + 1585152);
					accessway(((void *) basepointer) + 1589248);
					accessway(((void *) basepointer) + 1593344);
					accessway(((void *) basepointer) + 1597440);
					accessway(((void *) basepointer) + 1601536);
					accessway(((void *) basepointer) + 1605632);
					accessway(((void *) basepointer) + 1609728);
					accessway(((void *) basepointer) + 1613824);
					accessway(((void *) basepointer) + 1617920);
					accessway(((void *) basepointer) + 1622016);
					accessway(((void *) basepointer) + 1626112);
					accessway(((void *) basepointer) + 1630208);
					accessway(((void *) basepointer) + 1634304);
					accessway(((void *) basepointer) + 1638400);
					accessway(((void *) basepointer) + 1642496);
					accessway(((void *) basepointer) + 1646592);
					accessway(((void *) basepointer) + 1650688);
					accessway(((void *) basepointer) + 1654784);
					accessway(((void *) basepointer) + 1658880);
					accessway(((void *) basepointer) + 1662976);
					accessway(((void *) basepointer) + 1667072);
					accessway(((void *) basepointer) + 1671168);
					accessway(((void *) basepointer) + 1675264);
					accessway(((void *) basepointer) + 1679360);
					accessway(((void *) basepointer) + 1683456);
					accessway(((void *) basepointer) + 1687552);
					accessway(((void *) basepointer) + 1691648);
					accessway(((void *) basepointer) + 1695744);
					accessway(((void *) basepointer) + 1699840);
					accessway(((void *) basepointer) + 1703936);
					accessway(((void *) basepointer) + 1708032);
					accessway(((void *) basepointer) + 1712128);
					accessway(((void *) basepointer) + 1716224);
					accessway(((void *) basepointer) + 1720320);
					accessway(((void *) basepointer) + 1724416);
					accessway(((void *) basepointer) + 1728512);
					accessway(((void *) basepointer) + 1732608);
					accessway(((void *) basepointer) + 1736704);
					accessway(((void *) basepointer) + 1740800);
					accessway(((void *) basepointer) + 1744896);
					accessway(((void *) basepointer) + 1748992);
					accessway(((void *) basepointer) + 1753088);
					accessway(((void *) basepointer) + 1757184);
					accessway(((void *) basepointer) + 1761280);
					accessway(((void *) basepointer) + 1765376);
					accessway(((void *) basepointer) + 1769472);
					accessway(((void *) basepointer) + 1773568);
					accessway(((void *) basepointer) + 1777664);
					accessway(((void *) basepointer) + 1781760);
					accessway(((void *) basepointer) + 1785856);
					accessway(((void *) basepointer) + 1789952);
					accessway(((void *) basepointer) + 1794048);
					accessway(((void *) basepointer) + 1798144);
					accessway(((void *) basepointer) + 1802240);
					accessway(((void *) basepointer) + 1806336);
					accessway(((void *) basepointer) + 1810432);
					accessway(((void *) basepointer) + 1814528);
					accessway(((void *) basepointer) + 1818624);
					accessway(((void *) basepointer) + 1822720);
					accessway(((void *) basepointer) + 1826816);
					accessway(((void *) basepointer) + 1830912);
					accessway(((void *) basepointer) + 1835008);
					accessway(((void *) basepointer) + 1839104);
					accessway(((void *) basepointer) + 1843200);
					accessway(((void *) basepointer) + 1847296);
					accessway(((void *) basepointer) + 1851392);
					accessway(((void *) basepointer) + 1855488);
					accessway(((void *) basepointer) + 1859584);
					accessway(((void *) basepointer) + 1863680);
					accessway(((void *) basepointer) + 1867776);
					accessway(((void *) basepointer) + 1871872);
					accessway(((void *) basepointer) + 1875968);
					accessway(((void *) basepointer) + 1880064);
					accessway(((void *) basepointer) + 1884160);
					accessway(((void *) basepointer) + 1888256);
					accessway(((void *) basepointer) + 1892352);
					accessway(((void *) basepointer) + 1896448);
					accessway(((void *) basepointer) + 1900544);
					accessway(((void *) basepointer) + 1904640);
					accessway(((void *) basepointer) + 1908736);
					accessway(((void *) basepointer) + 1912832);
					accessway(((void *) basepointer) + 1916928);
					accessway(((void *) basepointer) + 1921024);
					accessway(((void *) basepointer) + 1925120);
					accessway(((void *) basepointer) + 1929216);
					accessway(((void *) basepointer) + 1933312);
					accessway(((void *) basepointer) + 1937408);
					accessway(((void *) basepointer) + 1941504);
					accessway(((void *) basepointer) + 1945600);
					accessway(((void *) basepointer) + 1949696);
					accessway(((void *) basepointer) + 1953792);
					accessway(((void *) basepointer) + 1957888);
					accessway(((void *) basepointer) + 1961984);
					accessway(((void *) basepointer) + 1966080);
					accessway(((void *) basepointer) + 1970176);
					accessway(((void *) basepointer) + 1974272);
					accessway(((void *) basepointer) + 1978368);
					accessway(((void *) basepointer) + 1982464);
					accessway(((void *) basepointer) + 1986560);
					accessway(((void *) basepointer) + 1990656);
					accessway(((void *) basepointer) + 1994752);
					accessway(((void *) basepointer) + 1998848);
					accessway(((void *) basepointer) + 2002944);
					accessway(((void *) basepointer) + 2007040);
					accessway(((void *) basepointer) + 2011136);
					accessway(((void *) basepointer) + 2015232);
					accessway(((void *) basepointer) + 2019328);
					accessway(((void *) basepointer) + 2023424);
					accessway(((void *) basepointer) + 2027520);
					accessway(((void *) basepointer) + 2031616);
					accessway(((void *) basepointer) + 2035712);
					accessway(((void *) basepointer) + 2039808);
					accessway(((void *) basepointer) + 2043904);
					accessway(((void *) basepointer) + 2048000);
					accessway(((void *) basepointer) + 2052096);
					accessway(((void *) basepointer) + 2056192);
					accessway(((void *) basepointer) + 2060288);
					accessway(((void *) basepointer) + 2064384);
					accessway(((void *) basepointer) + 2068480);
					accessway(((void *) basepointer) + 2072576);
					accessway(((void *) basepointer) + 2076672);
					accessway(((void *) basepointer) + 2080768);
					accessway(((void *) basepointer) + 2084864);
					accessway(((void *) basepointer) + 2088960);
					accessway(((void *) basepointer) + 2093056);
				}
			}
		}
		averageaccestime = (getcurrenttsc() - start) / (maxruns*(size/increment));
		analysis[idxanalyzed] = averageaccestime;
		//printf("\nCache with size: %d | Average Time: %d\n",size,averageaccestime);
	}

#endif
	return idxanalyzed;

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
	int sizeofevaluation = 1000;

	// Obtain cycles for the L1C
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(l1size, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the LLC
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the 2xLLC
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(ramsize, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);

	int scale = 1;

	// Generate the file to be used by gnuplot
	arraytocsv(dstfilename, scale, analysedsize, evaluation);
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




