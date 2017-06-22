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


#define LOOPUNROLLING 1

#define accessptr(addr) \
	asm volatile("mov (%0), %%eax\n":: "r" (addr): "%eax");

int depois_de_email_19_06_2017_TWO_hitevaluation(int vectorsize, int analyzedsize, int maxruns, int increment, int sizeofanalysisarray, unsigned int *analysis, int startanalysisidx) {
	int i, j, analysisidx = 0;
	char *basepointer = mmap(0, vectorsize, PROT_READ | PROT_WRITE,
	MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	//Init to populate pages
	for (i = 0; i < vectorsize; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) basepointer) + i;
		aux[0] = i;
	}

	//CREATE NEW DEFINE
#if LOOPUNROLLING == 0
	unsigned int averageaccestime = 0, idxanalyzed = 0;
	unsigned long long start;
	for(idxanalyzed = startanalysisidx; idxanalyzed < sizeofanalysisarray; ++idxanalyzed) {
		start = getcurrenttsc();
		for(j = 0; j < maxruns;++j){
			for (i = 0; i < analyzedsize; i += 64) {
				accessway(((void *) basepointer) + i);
				if(j==0){
					FILE* fptr;
					int i;

					fptr = fopen(PRIME_ANALYSIS_DATA_FILENAME, "w");
					for (i = 0; i < 1024; i+=1) {
						fprintf(fptr, "accessptr(((void *) basepointer)+i+%d);\n", i);
					}
					fclose(fptr);
				}
			}
		}
		averageaccestime = (getcurrenttsc() - start) / (maxruns*(analyzedsize/increment));
		//printf("Cache with size: %d | Average Time: %d\n",size,averageaccestime);
		analysis[idxanalyzed] = averageaccestime;
	}
#endif

#if LOOPUNROLLING == 1
	unsigned int averageaccestime = 0, idxanalyzed = 0;
	unsigned long long start;
	for( idxanalyzed = startanalysisidx; idxanalyzed < sizeofanalysisarray; ++idxanalyzed) {
		printf( "Idxanalyzed: %d\n", idxanalyzed);
		start = getcurrenttsc();
		for(j = 0; j < maxruns;++j){
			for(i = 0; i < analyzedsize;){
				accessptr(((void *) basepointer)+i+0);
				accessptr(((void *) basepointer)+i+1);
				accessptr(((void *) basepointer)+i+2);
				accessptr(((void *) basepointer)+i+3);
				accessptr(((void *) basepointer)+i+4);
				accessptr(((void *) basepointer)+i+5);
				accessptr(((void *) basepointer)+i+6);
				accessptr(((void *) basepointer)+i+7);
				accessptr(((void *) basepointer)+i+8);
				accessptr(((void *) basepointer)+i+9);
				accessptr(((void *) basepointer)+i+10);
				accessptr(((void *) basepointer)+i+11);
				accessptr(((void *) basepointer)+i+12);
				accessptr(((void *) basepointer)+i+13);
				accessptr(((void *) basepointer)+i+14);
				accessptr(((void *) basepointer)+i+15);
				accessptr(((void *) basepointer)+i+16);
				accessptr(((void *) basepointer)+i+17);
				accessptr(((void *) basepointer)+i+18);
				accessptr(((void *) basepointer)+i+19);
				accessptr(((void *) basepointer)+i+20);
				accessptr(((void *) basepointer)+i+21);
				accessptr(((void *) basepointer)+i+22);
				accessptr(((void *) basepointer)+i+23);
				accessptr(((void *) basepointer)+i+24);
				accessptr(((void *) basepointer)+i+25);
				accessptr(((void *) basepointer)+i+26);
				accessptr(((void *) basepointer)+i+27);
				accessptr(((void *) basepointer)+i+28);
				accessptr(((void *) basepointer)+i+29);
				accessptr(((void *) basepointer)+i+30);
				accessptr(((void *) basepointer)+i+31);
				accessptr(((void *) basepointer)+i+32);
				accessptr(((void *) basepointer)+i+33);
				accessptr(((void *) basepointer)+i+34);
				accessptr(((void *) basepointer)+i+35);
				accessptr(((void *) basepointer)+i+36);
				accessptr(((void *) basepointer)+i+37);
				accessptr(((void *) basepointer)+i+38);
				accessptr(((void *) basepointer)+i+39);
				accessptr(((void *) basepointer)+i+40);
				accessptr(((void *) basepointer)+i+41);
				accessptr(((void *) basepointer)+i+42);
				accessptr(((void *) basepointer)+i+43);
				accessptr(((void *) basepointer)+i+44);
				accessptr(((void *) basepointer)+i+45);
				accessptr(((void *) basepointer)+i+46);
				accessptr(((void *) basepointer)+i+47);
				accessptr(((void *) basepointer)+i+48);
				accessptr(((void *) basepointer)+i+49);
				accessptr(((void *) basepointer)+i+50);
				accessptr(((void *) basepointer)+i+51);
				accessptr(((void *) basepointer)+i+52);
				accessptr(((void *) basepointer)+i+53);
				accessptr(((void *) basepointer)+i+54);
				accessptr(((void *) basepointer)+i+55);
				accessptr(((void *) basepointer)+i+56);
				accessptr(((void *) basepointer)+i+57);
				accessptr(((void *) basepointer)+i+58);
				accessptr(((void *) basepointer)+i+59);
				accessptr(((void *) basepointer)+i+60);
				accessptr(((void *) basepointer)+i+61);
				accessptr(((void *) basepointer)+i+62);
				accessptr(((void *) basepointer)+i+63);
				accessptr(((void *) basepointer)+i+64);
				accessptr(((void *) basepointer)+i+65);
				accessptr(((void *) basepointer)+i+66);
				accessptr(((void *) basepointer)+i+67);
				accessptr(((void *) basepointer)+i+68);
				accessptr(((void *) basepointer)+i+69);
				accessptr(((void *) basepointer)+i+70);
				accessptr(((void *) basepointer)+i+71);
				accessptr(((void *) basepointer)+i+72);
				accessptr(((void *) basepointer)+i+73);
				accessptr(((void *) basepointer)+i+74);
				accessptr(((void *) basepointer)+i+75);
				accessptr(((void *) basepointer)+i+76);
				accessptr(((void *) basepointer)+i+77);
				accessptr(((void *) basepointer)+i+78);
				accessptr(((void *) basepointer)+i+79);
				accessptr(((void *) basepointer)+i+80);
				accessptr(((void *) basepointer)+i+81);
				accessptr(((void *) basepointer)+i+82);
				accessptr(((void *) basepointer)+i+83);
				accessptr(((void *) basepointer)+i+84);
				accessptr(((void *) basepointer)+i+85);
				accessptr(((void *) basepointer)+i+86);
				accessptr(((void *) basepointer)+i+87);
				accessptr(((void *) basepointer)+i+88);
				accessptr(((void *) basepointer)+i+89);
				accessptr(((void *) basepointer)+i+90);
				accessptr(((void *) basepointer)+i+91);
				accessptr(((void *) basepointer)+i+92);
				accessptr(((void *) basepointer)+i+93);
				accessptr(((void *) basepointer)+i+94);
				accessptr(((void *) basepointer)+i+95);
				accessptr(((void *) basepointer)+i+96);
				accessptr(((void *) basepointer)+i+97);
				accessptr(((void *) basepointer)+i+98);
				accessptr(((void *) basepointer)+i+99);
				accessptr(((void *) basepointer)+i+100);
				accessptr(((void *) basepointer)+i+101);
				accessptr(((void *) basepointer)+i+102);
				accessptr(((void *) basepointer)+i+103);
				accessptr(((void *) basepointer)+i+104);
				accessptr(((void *) basepointer)+i+105);
				accessptr(((void *) basepointer)+i+106);
				accessptr(((void *) basepointer)+i+107);
				accessptr(((void *) basepointer)+i+108);
				accessptr(((void *) basepointer)+i+109);
				accessptr(((void *) basepointer)+i+110);
				accessptr(((void *) basepointer)+i+111);
				accessptr(((void *) basepointer)+i+112);
				accessptr(((void *) basepointer)+i+113);
				accessptr(((void *) basepointer)+i+114);
				accessptr(((void *) basepointer)+i+115);
				accessptr(((void *) basepointer)+i+116);
				accessptr(((void *) basepointer)+i+117);
				accessptr(((void *) basepointer)+i+118);
				accessptr(((void *) basepointer)+i+119);
				accessptr(((void *) basepointer)+i+120);
				accessptr(((void *) basepointer)+i+121);
				accessptr(((void *) basepointer)+i+122);
				accessptr(((void *) basepointer)+i+123);
				accessptr(((void *) basepointer)+i+124);
				accessptr(((void *) basepointer)+i+125);
				accessptr(((void *) basepointer)+i+126);
				accessptr(((void *) basepointer)+i+127);
				accessptr(((void *) basepointer)+i+128);
				accessptr(((void *) basepointer)+i+129);
				accessptr(((void *) basepointer)+i+130);
				accessptr(((void *) basepointer)+i+131);
				accessptr(((void *) basepointer)+i+132);
				accessptr(((void *) basepointer)+i+133);
				accessptr(((void *) basepointer)+i+134);
				accessptr(((void *) basepointer)+i+135);
				accessptr(((void *) basepointer)+i+136);
				accessptr(((void *) basepointer)+i+137);
				accessptr(((void *) basepointer)+i+138);
				accessptr(((void *) basepointer)+i+139);
				accessptr(((void *) basepointer)+i+140);
				accessptr(((void *) basepointer)+i+141);
				accessptr(((void *) basepointer)+i+142);
				accessptr(((void *) basepointer)+i+143);
				accessptr(((void *) basepointer)+i+144);
				accessptr(((void *) basepointer)+i+145);
				accessptr(((void *) basepointer)+i+146);
				accessptr(((void *) basepointer)+i+147);
				accessptr(((void *) basepointer)+i+148);
				accessptr(((void *) basepointer)+i+149);
				accessptr(((void *) basepointer)+i+150);
				accessptr(((void *) basepointer)+i+151);
				accessptr(((void *) basepointer)+i+152);
				accessptr(((void *) basepointer)+i+153);
				accessptr(((void *) basepointer)+i+154);
				accessptr(((void *) basepointer)+i+155);
				accessptr(((void *) basepointer)+i+156);
				accessptr(((void *) basepointer)+i+157);
				accessptr(((void *) basepointer)+i+158);
				accessptr(((void *) basepointer)+i+159);
				accessptr(((void *) basepointer)+i+160);
				accessptr(((void *) basepointer)+i+161);
				accessptr(((void *) basepointer)+i+162);
				accessptr(((void *) basepointer)+i+163);
				accessptr(((void *) basepointer)+i+164);
				accessptr(((void *) basepointer)+i+165);
				accessptr(((void *) basepointer)+i+166);
				accessptr(((void *) basepointer)+i+167);
				accessptr(((void *) basepointer)+i+168);
				accessptr(((void *) basepointer)+i+169);
				accessptr(((void *) basepointer)+i+170);
				accessptr(((void *) basepointer)+i+171);
				accessptr(((void *) basepointer)+i+172);
				accessptr(((void *) basepointer)+i+173);
				accessptr(((void *) basepointer)+i+174);
				accessptr(((void *) basepointer)+i+175);
				accessptr(((void *) basepointer)+i+176);
				accessptr(((void *) basepointer)+i+177);
				accessptr(((void *) basepointer)+i+178);
				accessptr(((void *) basepointer)+i+179);
				accessptr(((void *) basepointer)+i+180);
				accessptr(((void *) basepointer)+i+181);
				accessptr(((void *) basepointer)+i+182);
				accessptr(((void *) basepointer)+i+183);
				accessptr(((void *) basepointer)+i+184);
				accessptr(((void *) basepointer)+i+185);
				accessptr(((void *) basepointer)+i+186);
				accessptr(((void *) basepointer)+i+187);
				accessptr(((void *) basepointer)+i+188);
				accessptr(((void *) basepointer)+i+189);
				accessptr(((void *) basepointer)+i+190);
				accessptr(((void *) basepointer)+i+191);
				accessptr(((void *) basepointer)+i+192);
				accessptr(((void *) basepointer)+i+193);
				accessptr(((void *) basepointer)+i+194);
				accessptr(((void *) basepointer)+i+195);
				accessptr(((void *) basepointer)+i+196);
				accessptr(((void *) basepointer)+i+197);
				accessptr(((void *) basepointer)+i+198);
				accessptr(((void *) basepointer)+i+199);
				accessptr(((void *) basepointer)+i+200);
				accessptr(((void *) basepointer)+i+201);
				accessptr(((void *) basepointer)+i+202);
				accessptr(((void *) basepointer)+i+203);
				accessptr(((void *) basepointer)+i+204);
				accessptr(((void *) basepointer)+i+205);
				accessptr(((void *) basepointer)+i+206);
				accessptr(((void *) basepointer)+i+207);
				accessptr(((void *) basepointer)+i+208);
				accessptr(((void *) basepointer)+i+209);
				accessptr(((void *) basepointer)+i+210);
				accessptr(((void *) basepointer)+i+211);
				accessptr(((void *) basepointer)+i+212);
				accessptr(((void *) basepointer)+i+213);
				accessptr(((void *) basepointer)+i+214);
				accessptr(((void *) basepointer)+i+215);
				accessptr(((void *) basepointer)+i+216);
				accessptr(((void *) basepointer)+i+217);
				accessptr(((void *) basepointer)+i+218);
				accessptr(((void *) basepointer)+i+219);
				accessptr(((void *) basepointer)+i+220);
				accessptr(((void *) basepointer)+i+221);
				accessptr(((void *) basepointer)+i+222);
				accessptr(((void *) basepointer)+i+223);
				accessptr(((void *) basepointer)+i+224);
				accessptr(((void *) basepointer)+i+225);
				accessptr(((void *) basepointer)+i+226);
				accessptr(((void *) basepointer)+i+227);
				accessptr(((void *) basepointer)+i+228);
				accessptr(((void *) basepointer)+i+229);
				accessptr(((void *) basepointer)+i+230);
				accessptr(((void *) basepointer)+i+231);
				accessptr(((void *) basepointer)+i+232);
				accessptr(((void *) basepointer)+i+233);
				accessptr(((void *) basepointer)+i+234);
				accessptr(((void *) basepointer)+i+235);
				accessptr(((void *) basepointer)+i+236);
				accessptr(((void *) basepointer)+i+237);
				accessptr(((void *) basepointer)+i+238);
				accessptr(((void *) basepointer)+i+239);
				accessptr(((void *) basepointer)+i+240);
				accessptr(((void *) basepointer)+i+241);
				accessptr(((void *) basepointer)+i+242);
				accessptr(((void *) basepointer)+i+243);
				accessptr(((void *) basepointer)+i+244);
				accessptr(((void *) basepointer)+i+245);
				accessptr(((void *) basepointer)+i+246);
				accessptr(((void *) basepointer)+i+247);
				accessptr(((void *) basepointer)+i+248);
				accessptr(((void *) basepointer)+i+249);
				accessptr(((void *) basepointer)+i+250);
				accessptr(((void *) basepointer)+i+251);
				accessptr(((void *) basepointer)+i+252);
				accessptr(((void *) basepointer)+i+253);
				accessptr(((void *) basepointer)+i+254);
				accessptr(((void *) basepointer)+i+255);
				accessptr(((void *) basepointer)+i+256);
				accessptr(((void *) basepointer)+i+257);
				accessptr(((void *) basepointer)+i+258);
				accessptr(((void *) basepointer)+i+259);
				accessptr(((void *) basepointer)+i+260);
				accessptr(((void *) basepointer)+i+261);
				accessptr(((void *) basepointer)+i+262);
				accessptr(((void *) basepointer)+i+263);
				accessptr(((void *) basepointer)+i+264);
				accessptr(((void *) basepointer)+i+265);
				accessptr(((void *) basepointer)+i+266);
				accessptr(((void *) basepointer)+i+267);
				accessptr(((void *) basepointer)+i+268);
				accessptr(((void *) basepointer)+i+269);
				accessptr(((void *) basepointer)+i+270);
				accessptr(((void *) basepointer)+i+271);
				accessptr(((void *) basepointer)+i+272);
				accessptr(((void *) basepointer)+i+273);
				accessptr(((void *) basepointer)+i+274);
				accessptr(((void *) basepointer)+i+275);
				accessptr(((void *) basepointer)+i+276);
				accessptr(((void *) basepointer)+i+277);
				accessptr(((void *) basepointer)+i+278);
				accessptr(((void *) basepointer)+i+279);
				accessptr(((void *) basepointer)+i+280);
				accessptr(((void *) basepointer)+i+281);
				accessptr(((void *) basepointer)+i+282);
				accessptr(((void *) basepointer)+i+283);
				accessptr(((void *) basepointer)+i+284);
				accessptr(((void *) basepointer)+i+285);
				accessptr(((void *) basepointer)+i+286);
				accessptr(((void *) basepointer)+i+287);
				accessptr(((void *) basepointer)+i+288);
				accessptr(((void *) basepointer)+i+289);
				accessptr(((void *) basepointer)+i+290);
				accessptr(((void *) basepointer)+i+291);
				accessptr(((void *) basepointer)+i+292);
				accessptr(((void *) basepointer)+i+293);
				accessptr(((void *) basepointer)+i+294);
				accessptr(((void *) basepointer)+i+295);
				accessptr(((void *) basepointer)+i+296);
				accessptr(((void *) basepointer)+i+297);
				accessptr(((void *) basepointer)+i+298);
				accessptr(((void *) basepointer)+i+299);
				accessptr(((void *) basepointer)+i+300);
				accessptr(((void *) basepointer)+i+301);
				accessptr(((void *) basepointer)+i+302);
				accessptr(((void *) basepointer)+i+303);
				accessptr(((void *) basepointer)+i+304);
				accessptr(((void *) basepointer)+i+305);
				accessptr(((void *) basepointer)+i+306);
				accessptr(((void *) basepointer)+i+307);
				accessptr(((void *) basepointer)+i+308);
				accessptr(((void *) basepointer)+i+309);
				accessptr(((void *) basepointer)+i+310);
				accessptr(((void *) basepointer)+i+311);
				accessptr(((void *) basepointer)+i+312);
				accessptr(((void *) basepointer)+i+313);
				accessptr(((void *) basepointer)+i+314);
				accessptr(((void *) basepointer)+i+315);
				accessptr(((void *) basepointer)+i+316);
				accessptr(((void *) basepointer)+i+317);
				accessptr(((void *) basepointer)+i+318);
				accessptr(((void *) basepointer)+i+319);
				accessptr(((void *) basepointer)+i+320);
				accessptr(((void *) basepointer)+i+321);
				accessptr(((void *) basepointer)+i+322);
				accessptr(((void *) basepointer)+i+323);
				accessptr(((void *) basepointer)+i+324);
				accessptr(((void *) basepointer)+i+325);
				accessptr(((void *) basepointer)+i+326);
				accessptr(((void *) basepointer)+i+327);
				accessptr(((void *) basepointer)+i+328);
				accessptr(((void *) basepointer)+i+329);
				accessptr(((void *) basepointer)+i+330);
				accessptr(((void *) basepointer)+i+331);
				accessptr(((void *) basepointer)+i+332);
				accessptr(((void *) basepointer)+i+333);
				accessptr(((void *) basepointer)+i+334);
				accessptr(((void *) basepointer)+i+335);
				accessptr(((void *) basepointer)+i+336);
				accessptr(((void *) basepointer)+i+337);
				accessptr(((void *) basepointer)+i+338);
				accessptr(((void *) basepointer)+i+339);
				accessptr(((void *) basepointer)+i+340);
				accessptr(((void *) basepointer)+i+341);
				accessptr(((void *) basepointer)+i+342);
				accessptr(((void *) basepointer)+i+343);
				accessptr(((void *) basepointer)+i+344);
				accessptr(((void *) basepointer)+i+345);
				accessptr(((void *) basepointer)+i+346);
				accessptr(((void *) basepointer)+i+347);
				accessptr(((void *) basepointer)+i+348);
				accessptr(((void *) basepointer)+i+349);
				accessptr(((void *) basepointer)+i+350);
				accessptr(((void *) basepointer)+i+351);
				accessptr(((void *) basepointer)+i+352);
				accessptr(((void *) basepointer)+i+353);
				accessptr(((void *) basepointer)+i+354);
				accessptr(((void *) basepointer)+i+355);
				accessptr(((void *) basepointer)+i+356);
				accessptr(((void *) basepointer)+i+357);
				accessptr(((void *) basepointer)+i+358);
				accessptr(((void *) basepointer)+i+359);
				accessptr(((void *) basepointer)+i+360);
				accessptr(((void *) basepointer)+i+361);
				accessptr(((void *) basepointer)+i+362);
				accessptr(((void *) basepointer)+i+363);
				accessptr(((void *) basepointer)+i+364);
				accessptr(((void *) basepointer)+i+365);
				accessptr(((void *) basepointer)+i+366);
				accessptr(((void *) basepointer)+i+367);
				accessptr(((void *) basepointer)+i+368);
				accessptr(((void *) basepointer)+i+369);
				accessptr(((void *) basepointer)+i+370);
				accessptr(((void *) basepointer)+i+371);
				accessptr(((void *) basepointer)+i+372);
				accessptr(((void *) basepointer)+i+373);
				accessptr(((void *) basepointer)+i+374);
				accessptr(((void *) basepointer)+i+375);
				accessptr(((void *) basepointer)+i+376);
				accessptr(((void *) basepointer)+i+377);
				accessptr(((void *) basepointer)+i+378);
				accessptr(((void *) basepointer)+i+379);
				accessptr(((void *) basepointer)+i+380);
				accessptr(((void *) basepointer)+i+381);
				accessptr(((void *) basepointer)+i+382);
				accessptr(((void *) basepointer)+i+383);
				accessptr(((void *) basepointer)+i+384);
				accessptr(((void *) basepointer)+i+385);
				accessptr(((void *) basepointer)+i+386);
				accessptr(((void *) basepointer)+i+387);
				accessptr(((void *) basepointer)+i+388);
				accessptr(((void *) basepointer)+i+389);
				accessptr(((void *) basepointer)+i+390);
				accessptr(((void *) basepointer)+i+391);
				accessptr(((void *) basepointer)+i+392);
				accessptr(((void *) basepointer)+i+393);
				accessptr(((void *) basepointer)+i+394);
				accessptr(((void *) basepointer)+i+395);
				accessptr(((void *) basepointer)+i+396);
				accessptr(((void *) basepointer)+i+397);
				accessptr(((void *) basepointer)+i+398);
				accessptr(((void *) basepointer)+i+399);
				accessptr(((void *) basepointer)+i+400);
				accessptr(((void *) basepointer)+i+401);
				accessptr(((void *) basepointer)+i+402);
				accessptr(((void *) basepointer)+i+403);
				accessptr(((void *) basepointer)+i+404);
				accessptr(((void *) basepointer)+i+405);
				accessptr(((void *) basepointer)+i+406);
				accessptr(((void *) basepointer)+i+407);
				accessptr(((void *) basepointer)+i+408);
				accessptr(((void *) basepointer)+i+409);
				accessptr(((void *) basepointer)+i+410);
				accessptr(((void *) basepointer)+i+411);
				accessptr(((void *) basepointer)+i+412);
				accessptr(((void *) basepointer)+i+413);
				accessptr(((void *) basepointer)+i+414);
				accessptr(((void *) basepointer)+i+415);
				accessptr(((void *) basepointer)+i+416);
				accessptr(((void *) basepointer)+i+417);
				accessptr(((void *) basepointer)+i+418);
				accessptr(((void *) basepointer)+i+419);
				accessptr(((void *) basepointer)+i+420);
				accessptr(((void *) basepointer)+i+421);
				accessptr(((void *) basepointer)+i+422);
				accessptr(((void *) basepointer)+i+423);
				accessptr(((void *) basepointer)+i+424);
				accessptr(((void *) basepointer)+i+425);
				accessptr(((void *) basepointer)+i+426);
				accessptr(((void *) basepointer)+i+427);
				accessptr(((void *) basepointer)+i+428);
				accessptr(((void *) basepointer)+i+429);
				accessptr(((void *) basepointer)+i+430);
				accessptr(((void *) basepointer)+i+431);
				accessptr(((void *) basepointer)+i+432);
				accessptr(((void *) basepointer)+i+433);
				accessptr(((void *) basepointer)+i+434);
				accessptr(((void *) basepointer)+i+435);
				accessptr(((void *) basepointer)+i+436);
				accessptr(((void *) basepointer)+i+437);
				accessptr(((void *) basepointer)+i+438);
				accessptr(((void *) basepointer)+i+439);
				accessptr(((void *) basepointer)+i+440);
				accessptr(((void *) basepointer)+i+441);
				accessptr(((void *) basepointer)+i+442);
				accessptr(((void *) basepointer)+i+443);
				accessptr(((void *) basepointer)+i+444);
				accessptr(((void *) basepointer)+i+445);
				accessptr(((void *) basepointer)+i+446);
				accessptr(((void *) basepointer)+i+447);
				accessptr(((void *) basepointer)+i+448);
				accessptr(((void *) basepointer)+i+449);
				accessptr(((void *) basepointer)+i+450);
				accessptr(((void *) basepointer)+i+451);
				accessptr(((void *) basepointer)+i+452);
				accessptr(((void *) basepointer)+i+453);
				accessptr(((void *) basepointer)+i+454);
				accessptr(((void *) basepointer)+i+455);
				accessptr(((void *) basepointer)+i+456);
				accessptr(((void *) basepointer)+i+457);
				accessptr(((void *) basepointer)+i+458);
				accessptr(((void *) basepointer)+i+459);
				accessptr(((void *) basepointer)+i+460);
				accessptr(((void *) basepointer)+i+461);
				accessptr(((void *) basepointer)+i+462);
				accessptr(((void *) basepointer)+i+463);
				accessptr(((void *) basepointer)+i+464);
				accessptr(((void *) basepointer)+i+465);
				accessptr(((void *) basepointer)+i+466);
				accessptr(((void *) basepointer)+i+467);
				accessptr(((void *) basepointer)+i+468);
				accessptr(((void *) basepointer)+i+469);
				accessptr(((void *) basepointer)+i+470);
				accessptr(((void *) basepointer)+i+471);
				accessptr(((void *) basepointer)+i+472);
				accessptr(((void *) basepointer)+i+473);
				accessptr(((void *) basepointer)+i+474);
				accessptr(((void *) basepointer)+i+475);
				accessptr(((void *) basepointer)+i+476);
				accessptr(((void *) basepointer)+i+477);
				accessptr(((void *) basepointer)+i+478);
				accessptr(((void *) basepointer)+i+479);
				accessptr(((void *) basepointer)+i+480);
				accessptr(((void *) basepointer)+i+481);
				accessptr(((void *) basepointer)+i+482);
				accessptr(((void *) basepointer)+i+483);
				accessptr(((void *) basepointer)+i+484);
				accessptr(((void *) basepointer)+i+485);
				accessptr(((void *) basepointer)+i+486);
				accessptr(((void *) basepointer)+i+487);
				accessptr(((void *) basepointer)+i+488);
				accessptr(((void *) basepointer)+i+489);
				accessptr(((void *) basepointer)+i+490);
				accessptr(((void *) basepointer)+i+491);
				accessptr(((void *) basepointer)+i+492);
				accessptr(((void *) basepointer)+i+493);
				accessptr(((void *) basepointer)+i+494);
				accessptr(((void *) basepointer)+i+495);
				accessptr(((void *) basepointer)+i+496);
				accessptr(((void *) basepointer)+i+497);
				accessptr(((void *) basepointer)+i+498);
				accessptr(((void *) basepointer)+i+499);
				accessptr(((void *) basepointer)+i+500);
				accessptr(((void *) basepointer)+i+501);
				accessptr(((void *) basepointer)+i+502);
				accessptr(((void *) basepointer)+i+503);
				accessptr(((void *) basepointer)+i+504);
				accessptr(((void *) basepointer)+i+505);
				accessptr(((void *) basepointer)+i+506);
				accessptr(((void *) basepointer)+i+507);
				accessptr(((void *) basepointer)+i+508);
				accessptr(((void *) basepointer)+i+509);
				accessptr(((void *) basepointer)+i+510);
				accessptr(((void *) basepointer)+i+511);
				accessptr(((void *) basepointer)+i+512);
				accessptr(((void *) basepointer)+i+513);
				accessptr(((void *) basepointer)+i+514);
				accessptr(((void *) basepointer)+i+515);
				accessptr(((void *) basepointer)+i+516);
				accessptr(((void *) basepointer)+i+517);
				accessptr(((void *) basepointer)+i+518);
				accessptr(((void *) basepointer)+i+519);
				accessptr(((void *) basepointer)+i+520);
				accessptr(((void *) basepointer)+i+521);
				accessptr(((void *) basepointer)+i+522);
				accessptr(((void *) basepointer)+i+523);
				accessptr(((void *) basepointer)+i+524);
				accessptr(((void *) basepointer)+i+525);
				accessptr(((void *) basepointer)+i+526);
				accessptr(((void *) basepointer)+i+527);
				accessptr(((void *) basepointer)+i+528);
				accessptr(((void *) basepointer)+i+529);
				accessptr(((void *) basepointer)+i+530);
				accessptr(((void *) basepointer)+i+531);
				accessptr(((void *) basepointer)+i+532);
				accessptr(((void *) basepointer)+i+533);
				accessptr(((void *) basepointer)+i+534);
				accessptr(((void *) basepointer)+i+535);
				accessptr(((void *) basepointer)+i+536);
				accessptr(((void *) basepointer)+i+537);
				accessptr(((void *) basepointer)+i+538);
				accessptr(((void *) basepointer)+i+539);
				accessptr(((void *) basepointer)+i+540);
				accessptr(((void *) basepointer)+i+541);
				accessptr(((void *) basepointer)+i+542);
				accessptr(((void *) basepointer)+i+543);
				accessptr(((void *) basepointer)+i+544);
				accessptr(((void *) basepointer)+i+545);
				accessptr(((void *) basepointer)+i+546);
				accessptr(((void *) basepointer)+i+547);
				accessptr(((void *) basepointer)+i+548);
				accessptr(((void *) basepointer)+i+549);
				accessptr(((void *) basepointer)+i+550);
				accessptr(((void *) basepointer)+i+551);
				accessptr(((void *) basepointer)+i+552);
				accessptr(((void *) basepointer)+i+553);
				accessptr(((void *) basepointer)+i+554);
				accessptr(((void *) basepointer)+i+555);
				accessptr(((void *) basepointer)+i+556);
				accessptr(((void *) basepointer)+i+557);
				accessptr(((void *) basepointer)+i+558);
				accessptr(((void *) basepointer)+i+559);
				accessptr(((void *) basepointer)+i+560);
				accessptr(((void *) basepointer)+i+561);
				accessptr(((void *) basepointer)+i+562);
				accessptr(((void *) basepointer)+i+563);
				accessptr(((void *) basepointer)+i+564);
				accessptr(((void *) basepointer)+i+565);
				accessptr(((void *) basepointer)+i+566);
				accessptr(((void *) basepointer)+i+567);
				accessptr(((void *) basepointer)+i+568);
				accessptr(((void *) basepointer)+i+569);
				accessptr(((void *) basepointer)+i+570);
				accessptr(((void *) basepointer)+i+571);
				accessptr(((void *) basepointer)+i+572);
				accessptr(((void *) basepointer)+i+573);
				accessptr(((void *) basepointer)+i+574);
				accessptr(((void *) basepointer)+i+575);
				accessptr(((void *) basepointer)+i+576);
				accessptr(((void *) basepointer)+i+577);
				accessptr(((void *) basepointer)+i+578);
				accessptr(((void *) basepointer)+i+579);
				accessptr(((void *) basepointer)+i+580);
				accessptr(((void *) basepointer)+i+581);
				accessptr(((void *) basepointer)+i+582);
				accessptr(((void *) basepointer)+i+583);
				accessptr(((void *) basepointer)+i+584);
				accessptr(((void *) basepointer)+i+585);
				accessptr(((void *) basepointer)+i+586);
				accessptr(((void *) basepointer)+i+587);
				accessptr(((void *) basepointer)+i+588);
				accessptr(((void *) basepointer)+i+589);
				accessptr(((void *) basepointer)+i+590);
				accessptr(((void *) basepointer)+i+591);
				accessptr(((void *) basepointer)+i+592);
				accessptr(((void *) basepointer)+i+593);
				accessptr(((void *) basepointer)+i+594);
				accessptr(((void *) basepointer)+i+595);
				accessptr(((void *) basepointer)+i+596);
				accessptr(((void *) basepointer)+i+597);
				accessptr(((void *) basepointer)+i+598);
				accessptr(((void *) basepointer)+i+599);
				accessptr(((void *) basepointer)+i+600);
				accessptr(((void *) basepointer)+i+601);
				accessptr(((void *) basepointer)+i+602);
				accessptr(((void *) basepointer)+i+603);
				accessptr(((void *) basepointer)+i+604);
				accessptr(((void *) basepointer)+i+605);
				accessptr(((void *) basepointer)+i+606);
				accessptr(((void *) basepointer)+i+607);
				accessptr(((void *) basepointer)+i+608);
				accessptr(((void *) basepointer)+i+609);
				accessptr(((void *) basepointer)+i+610);
				accessptr(((void *) basepointer)+i+611);
				accessptr(((void *) basepointer)+i+612);
				accessptr(((void *) basepointer)+i+613);
				accessptr(((void *) basepointer)+i+614);
				accessptr(((void *) basepointer)+i+615);
				accessptr(((void *) basepointer)+i+616);
				accessptr(((void *) basepointer)+i+617);
				accessptr(((void *) basepointer)+i+618);
				accessptr(((void *) basepointer)+i+619);
				accessptr(((void *) basepointer)+i+620);
				accessptr(((void *) basepointer)+i+621);
				accessptr(((void *) basepointer)+i+622);
				accessptr(((void *) basepointer)+i+623);
				accessptr(((void *) basepointer)+i+624);
				accessptr(((void *) basepointer)+i+625);
				accessptr(((void *) basepointer)+i+626);
				accessptr(((void *) basepointer)+i+627);
				accessptr(((void *) basepointer)+i+628);
				accessptr(((void *) basepointer)+i+629);
				accessptr(((void *) basepointer)+i+630);
				accessptr(((void *) basepointer)+i+631);
				accessptr(((void *) basepointer)+i+632);
				accessptr(((void *) basepointer)+i+633);
				accessptr(((void *) basepointer)+i+634);
				accessptr(((void *) basepointer)+i+635);
				accessptr(((void *) basepointer)+i+636);
				accessptr(((void *) basepointer)+i+637);
				accessptr(((void *) basepointer)+i+638);
				accessptr(((void *) basepointer)+i+639);
				accessptr(((void *) basepointer)+i+640);
				accessptr(((void *) basepointer)+i+641);
				accessptr(((void *) basepointer)+i+642);
				accessptr(((void *) basepointer)+i+643);
				accessptr(((void *) basepointer)+i+644);
				accessptr(((void *) basepointer)+i+645);
				accessptr(((void *) basepointer)+i+646);
				accessptr(((void *) basepointer)+i+647);
				accessptr(((void *) basepointer)+i+648);
				accessptr(((void *) basepointer)+i+649);
				accessptr(((void *) basepointer)+i+650);
				accessptr(((void *) basepointer)+i+651);
				accessptr(((void *) basepointer)+i+652);
				accessptr(((void *) basepointer)+i+653);
				accessptr(((void *) basepointer)+i+654);
				accessptr(((void *) basepointer)+i+655);
				accessptr(((void *) basepointer)+i+656);
				accessptr(((void *) basepointer)+i+657);
				accessptr(((void *) basepointer)+i+658);
				accessptr(((void *) basepointer)+i+659);
				accessptr(((void *) basepointer)+i+660);
				accessptr(((void *) basepointer)+i+661);
				accessptr(((void *) basepointer)+i+662);
				accessptr(((void *) basepointer)+i+663);
				accessptr(((void *) basepointer)+i+664);
				accessptr(((void *) basepointer)+i+665);
				accessptr(((void *) basepointer)+i+666);
				accessptr(((void *) basepointer)+i+667);
				accessptr(((void *) basepointer)+i+668);
				accessptr(((void *) basepointer)+i+669);
				accessptr(((void *) basepointer)+i+670);
				accessptr(((void *) basepointer)+i+671);
				accessptr(((void *) basepointer)+i+672);
				accessptr(((void *) basepointer)+i+673);
				accessptr(((void *) basepointer)+i+674);
				accessptr(((void *) basepointer)+i+675);
				accessptr(((void *) basepointer)+i+676);
				accessptr(((void *) basepointer)+i+677);
				accessptr(((void *) basepointer)+i+678);
				accessptr(((void *) basepointer)+i+679);
				accessptr(((void *) basepointer)+i+680);
				accessptr(((void *) basepointer)+i+681);
				accessptr(((void *) basepointer)+i+682);
				accessptr(((void *) basepointer)+i+683);
				accessptr(((void *) basepointer)+i+684);
				accessptr(((void *) basepointer)+i+685);
				accessptr(((void *) basepointer)+i+686);
				accessptr(((void *) basepointer)+i+687);
				accessptr(((void *) basepointer)+i+688);
				accessptr(((void *) basepointer)+i+689);
				accessptr(((void *) basepointer)+i+690);
				accessptr(((void *) basepointer)+i+691);
				accessptr(((void *) basepointer)+i+692);
				accessptr(((void *) basepointer)+i+693);
				accessptr(((void *) basepointer)+i+694);
				accessptr(((void *) basepointer)+i+695);
				accessptr(((void *) basepointer)+i+696);
				accessptr(((void *) basepointer)+i+697);
				accessptr(((void *) basepointer)+i+698);
				accessptr(((void *) basepointer)+i+699);
				accessptr(((void *) basepointer)+i+700);
				accessptr(((void *) basepointer)+i+701);
				accessptr(((void *) basepointer)+i+702);
				accessptr(((void *) basepointer)+i+703);
				accessptr(((void *) basepointer)+i+704);
				accessptr(((void *) basepointer)+i+705);
				accessptr(((void *) basepointer)+i+706);
				accessptr(((void *) basepointer)+i+707);
				accessptr(((void *) basepointer)+i+708);
				accessptr(((void *) basepointer)+i+709);
				accessptr(((void *) basepointer)+i+710);
				accessptr(((void *) basepointer)+i+711);
				accessptr(((void *) basepointer)+i+712);
				accessptr(((void *) basepointer)+i+713);
				accessptr(((void *) basepointer)+i+714);
				accessptr(((void *) basepointer)+i+715);
				accessptr(((void *) basepointer)+i+716);
				accessptr(((void *) basepointer)+i+717);
				accessptr(((void *) basepointer)+i+718);
				accessptr(((void *) basepointer)+i+719);
				accessptr(((void *) basepointer)+i+720);
				accessptr(((void *) basepointer)+i+721);
				accessptr(((void *) basepointer)+i+722);
				accessptr(((void *) basepointer)+i+723);
				accessptr(((void *) basepointer)+i+724);
				accessptr(((void *) basepointer)+i+725);
				accessptr(((void *) basepointer)+i+726);
				accessptr(((void *) basepointer)+i+727);
				accessptr(((void *) basepointer)+i+728);
				accessptr(((void *) basepointer)+i+729);
				accessptr(((void *) basepointer)+i+730);
				accessptr(((void *) basepointer)+i+731);
				accessptr(((void *) basepointer)+i+732);
				accessptr(((void *) basepointer)+i+733);
				accessptr(((void *) basepointer)+i+734);
				accessptr(((void *) basepointer)+i+735);
				accessptr(((void *) basepointer)+i+736);
				accessptr(((void *) basepointer)+i+737);
				accessptr(((void *) basepointer)+i+738);
				accessptr(((void *) basepointer)+i+739);
				accessptr(((void *) basepointer)+i+740);
				accessptr(((void *) basepointer)+i+741);
				accessptr(((void *) basepointer)+i+742);
				accessptr(((void *) basepointer)+i+743);
				accessptr(((void *) basepointer)+i+744);
				accessptr(((void *) basepointer)+i+745);
				accessptr(((void *) basepointer)+i+746);
				accessptr(((void *) basepointer)+i+747);
				accessptr(((void *) basepointer)+i+748);
				accessptr(((void *) basepointer)+i+749);
				accessptr(((void *) basepointer)+i+750);
				accessptr(((void *) basepointer)+i+751);
				accessptr(((void *) basepointer)+i+752);
				accessptr(((void *) basepointer)+i+753);
				accessptr(((void *) basepointer)+i+754);
				accessptr(((void *) basepointer)+i+755);
				accessptr(((void *) basepointer)+i+756);
				accessptr(((void *) basepointer)+i+757);
				accessptr(((void *) basepointer)+i+758);
				accessptr(((void *) basepointer)+i+759);
				accessptr(((void *) basepointer)+i+760);
				accessptr(((void *) basepointer)+i+761);
				accessptr(((void *) basepointer)+i+762);
				accessptr(((void *) basepointer)+i+763);
				accessptr(((void *) basepointer)+i+764);
				accessptr(((void *) basepointer)+i+765);
				accessptr(((void *) basepointer)+i+766);
				accessptr(((void *) basepointer)+i+767);
				accessptr(((void *) basepointer)+i+768);
				accessptr(((void *) basepointer)+i+769);
				accessptr(((void *) basepointer)+i+770);
				accessptr(((void *) basepointer)+i+771);
				accessptr(((void *) basepointer)+i+772);
				accessptr(((void *) basepointer)+i+773);
				accessptr(((void *) basepointer)+i+774);
				accessptr(((void *) basepointer)+i+775);
				accessptr(((void *) basepointer)+i+776);
				accessptr(((void *) basepointer)+i+777);
				accessptr(((void *) basepointer)+i+778);
				accessptr(((void *) basepointer)+i+779);
				accessptr(((void *) basepointer)+i+780);
				accessptr(((void *) basepointer)+i+781);
				accessptr(((void *) basepointer)+i+782);
				accessptr(((void *) basepointer)+i+783);
				accessptr(((void *) basepointer)+i+784);
				accessptr(((void *) basepointer)+i+785);
				accessptr(((void *) basepointer)+i+786);
				accessptr(((void *) basepointer)+i+787);
				accessptr(((void *) basepointer)+i+788);
				accessptr(((void *) basepointer)+i+789);
				accessptr(((void *) basepointer)+i+790);
				accessptr(((void *) basepointer)+i+791);
				accessptr(((void *) basepointer)+i+792);
				accessptr(((void *) basepointer)+i+793);
				accessptr(((void *) basepointer)+i+794);
				accessptr(((void *) basepointer)+i+795);
				accessptr(((void *) basepointer)+i+796);
				accessptr(((void *) basepointer)+i+797);
				accessptr(((void *) basepointer)+i+798);
				accessptr(((void *) basepointer)+i+799);
				accessptr(((void *) basepointer)+i+800);
				accessptr(((void *) basepointer)+i+801);
				accessptr(((void *) basepointer)+i+802);
				accessptr(((void *) basepointer)+i+803);
				accessptr(((void *) basepointer)+i+804);
				accessptr(((void *) basepointer)+i+805);
				accessptr(((void *) basepointer)+i+806);
				accessptr(((void *) basepointer)+i+807);
				accessptr(((void *) basepointer)+i+808);
				accessptr(((void *) basepointer)+i+809);
				accessptr(((void *) basepointer)+i+810);
				accessptr(((void *) basepointer)+i+811);
				accessptr(((void *) basepointer)+i+812);
				accessptr(((void *) basepointer)+i+813);
				accessptr(((void *) basepointer)+i+814);
				accessptr(((void *) basepointer)+i+815);
				accessptr(((void *) basepointer)+i+816);
				accessptr(((void *) basepointer)+i+817);
				accessptr(((void *) basepointer)+i+818);
				accessptr(((void *) basepointer)+i+819);
				accessptr(((void *) basepointer)+i+820);
				accessptr(((void *) basepointer)+i+821);
				accessptr(((void *) basepointer)+i+822);
				accessptr(((void *) basepointer)+i+823);
				accessptr(((void *) basepointer)+i+824);
				accessptr(((void *) basepointer)+i+825);
				accessptr(((void *) basepointer)+i+826);
				accessptr(((void *) basepointer)+i+827);
				accessptr(((void *) basepointer)+i+828);
				accessptr(((void *) basepointer)+i+829);
				accessptr(((void *) basepointer)+i+830);
				accessptr(((void *) basepointer)+i+831);
				accessptr(((void *) basepointer)+i+832);
				accessptr(((void *) basepointer)+i+833);
				accessptr(((void *) basepointer)+i+834);
				accessptr(((void *) basepointer)+i+835);
				accessptr(((void *) basepointer)+i+836);
				accessptr(((void *) basepointer)+i+837);
				accessptr(((void *) basepointer)+i+838);
				accessptr(((void *) basepointer)+i+839);
				accessptr(((void *) basepointer)+i+840);
				accessptr(((void *) basepointer)+i+841);
				accessptr(((void *) basepointer)+i+842);
				accessptr(((void *) basepointer)+i+843);
				accessptr(((void *) basepointer)+i+844);
				accessptr(((void *) basepointer)+i+845);
				accessptr(((void *) basepointer)+i+846);
				accessptr(((void *) basepointer)+i+847);
				accessptr(((void *) basepointer)+i+848);
				accessptr(((void *) basepointer)+i+849);
				accessptr(((void *) basepointer)+i+850);
				accessptr(((void *) basepointer)+i+851);
				accessptr(((void *) basepointer)+i+852);
				accessptr(((void *) basepointer)+i+853);
				accessptr(((void *) basepointer)+i+854);
				accessptr(((void *) basepointer)+i+855);
				accessptr(((void *) basepointer)+i+856);
				accessptr(((void *) basepointer)+i+857);
				accessptr(((void *) basepointer)+i+858);
				accessptr(((void *) basepointer)+i+859);
				accessptr(((void *) basepointer)+i+860);
				accessptr(((void *) basepointer)+i+861);
				accessptr(((void *) basepointer)+i+862);
				accessptr(((void *) basepointer)+i+863);
				accessptr(((void *) basepointer)+i+864);
				accessptr(((void *) basepointer)+i+865);
				accessptr(((void *) basepointer)+i+866);
				accessptr(((void *) basepointer)+i+867);
				accessptr(((void *) basepointer)+i+868);
				accessptr(((void *) basepointer)+i+869);
				accessptr(((void *) basepointer)+i+870);
				accessptr(((void *) basepointer)+i+871);
				accessptr(((void *) basepointer)+i+872);
				accessptr(((void *) basepointer)+i+873);
				accessptr(((void *) basepointer)+i+874);
				accessptr(((void *) basepointer)+i+875);
				accessptr(((void *) basepointer)+i+876);
				accessptr(((void *) basepointer)+i+877);
				accessptr(((void *) basepointer)+i+878);
				accessptr(((void *) basepointer)+i+879);
				accessptr(((void *) basepointer)+i+880);
				accessptr(((void *) basepointer)+i+881);
				accessptr(((void *) basepointer)+i+882);
				accessptr(((void *) basepointer)+i+883);
				accessptr(((void *) basepointer)+i+884);
				accessptr(((void *) basepointer)+i+885);
				accessptr(((void *) basepointer)+i+886);
				accessptr(((void *) basepointer)+i+887);
				accessptr(((void *) basepointer)+i+888);
				accessptr(((void *) basepointer)+i+889);
				accessptr(((void *) basepointer)+i+890);
				accessptr(((void *) basepointer)+i+891);
				accessptr(((void *) basepointer)+i+892);
				accessptr(((void *) basepointer)+i+893);
				accessptr(((void *) basepointer)+i+894);
				accessptr(((void *) basepointer)+i+895);
				accessptr(((void *) basepointer)+i+896);
				accessptr(((void *) basepointer)+i+897);
				accessptr(((void *) basepointer)+i+898);
				accessptr(((void *) basepointer)+i+899);
				accessptr(((void *) basepointer)+i+900);
				accessptr(((void *) basepointer)+i+901);
				accessptr(((void *) basepointer)+i+902);
				accessptr(((void *) basepointer)+i+903);
				accessptr(((void *) basepointer)+i+904);
				accessptr(((void *) basepointer)+i+905);
				accessptr(((void *) basepointer)+i+906);
				accessptr(((void *) basepointer)+i+907);
				accessptr(((void *) basepointer)+i+908);
				accessptr(((void *) basepointer)+i+909);
				accessptr(((void *) basepointer)+i+910);
				accessptr(((void *) basepointer)+i+911);
				accessptr(((void *) basepointer)+i+912);
				accessptr(((void *) basepointer)+i+913);
				accessptr(((void *) basepointer)+i+914);
				accessptr(((void *) basepointer)+i+915);
				accessptr(((void *) basepointer)+i+916);
				accessptr(((void *) basepointer)+i+917);
				accessptr(((void *) basepointer)+i+918);
				accessptr(((void *) basepointer)+i+919);
				accessptr(((void *) basepointer)+i+920);
				accessptr(((void *) basepointer)+i+921);
				accessptr(((void *) basepointer)+i+922);
				accessptr(((void *) basepointer)+i+923);
				accessptr(((void *) basepointer)+i+924);
				accessptr(((void *) basepointer)+i+925);
				accessptr(((void *) basepointer)+i+926);
				accessptr(((void *) basepointer)+i+927);
				accessptr(((void *) basepointer)+i+928);
				accessptr(((void *) basepointer)+i+929);
				accessptr(((void *) basepointer)+i+930);
				accessptr(((void *) basepointer)+i+931);
				accessptr(((void *) basepointer)+i+932);
				accessptr(((void *) basepointer)+i+933);
				accessptr(((void *) basepointer)+i+934);
				accessptr(((void *) basepointer)+i+935);
				accessptr(((void *) basepointer)+i+936);
				accessptr(((void *) basepointer)+i+937);
				accessptr(((void *) basepointer)+i+938);
				accessptr(((void *) basepointer)+i+939);
				accessptr(((void *) basepointer)+i+940);
				accessptr(((void *) basepointer)+i+941);
				accessptr(((void *) basepointer)+i+942);
				accessptr(((void *) basepointer)+i+943);
				accessptr(((void *) basepointer)+i+944);
				accessptr(((void *) basepointer)+i+945);
				accessptr(((void *) basepointer)+i+946);
				accessptr(((void *) basepointer)+i+947);
				accessptr(((void *) basepointer)+i+948);
				accessptr(((void *) basepointer)+i+949);
				accessptr(((void *) basepointer)+i+950);
				accessptr(((void *) basepointer)+i+951);
				accessptr(((void *) basepointer)+i+952);
				accessptr(((void *) basepointer)+i+953);
				accessptr(((void *) basepointer)+i+954);
				accessptr(((void *) basepointer)+i+955);
				accessptr(((void *) basepointer)+i+956);
				accessptr(((void *) basepointer)+i+957);
				accessptr(((void *) basepointer)+i+958);
				accessptr(((void *) basepointer)+i+959);
				accessptr(((void *) basepointer)+i+960);
				accessptr(((void *) basepointer)+i+961);
				accessptr(((void *) basepointer)+i+962);
				accessptr(((void *) basepointer)+i+963);
				accessptr(((void *) basepointer)+i+964);
				accessptr(((void *) basepointer)+i+965);
				accessptr(((void *) basepointer)+i+966);
				accessptr(((void *) basepointer)+i+967);
				accessptr(((void *) basepointer)+i+968);
				accessptr(((void *) basepointer)+i+969);
				accessptr(((void *) basepointer)+i+970);
				accessptr(((void *) basepointer)+i+971);
				accessptr(((void *) basepointer)+i+972);
				accessptr(((void *) basepointer)+i+973);
				accessptr(((void *) basepointer)+i+974);
				accessptr(((void *) basepointer)+i+975);
				accessptr(((void *) basepointer)+i+976);
				accessptr(((void *) basepointer)+i+977);
				accessptr(((void *) basepointer)+i+978);
				accessptr(((void *) basepointer)+i+979);
				accessptr(((void *) basepointer)+i+980);
				accessptr(((void *) basepointer)+i+981);
				accessptr(((void *) basepointer)+i+982);
				accessptr(((void *) basepointer)+i+983);
				accessptr(((void *) basepointer)+i+984);
				accessptr(((void *) basepointer)+i+985);
				accessptr(((void *) basepointer)+i+986);
				accessptr(((void *) basepointer)+i+987);
				accessptr(((void *) basepointer)+i+988);
				accessptr(((void *) basepointer)+i+989);
				accessptr(((void *) basepointer)+i+990);
				accessptr(((void *) basepointer)+i+991);
				accessptr(((void *) basepointer)+i+992);
				accessptr(((void *) basepointer)+i+993);
				accessptr(((void *) basepointer)+i+994);
				accessptr(((void *) basepointer)+i+995);
				accessptr(((void *) basepointer)+i+996);
				accessptr(((void *) basepointer)+i+997);
				accessptr(((void *) basepointer)+i+998);
				accessptr(((void *) basepointer)+i+999);
				accessptr(((void *) basepointer)+i+1000);
				accessptr(((void *) basepointer)+i+1001);
				accessptr(((void *) basepointer)+i+1002);
				accessptr(((void *) basepointer)+i+1003);
				accessptr(((void *) basepointer)+i+1004);
				accessptr(((void *) basepointer)+i+1005);
				accessptr(((void *) basepointer)+i+1006);
				accessptr(((void *) basepointer)+i+1007);
				accessptr(((void *) basepointer)+i+1008);
				accessptr(((void *) basepointer)+i+1009);
				accessptr(((void *) basepointer)+i+1010);
				accessptr(((void *) basepointer)+i+1011);
				accessptr(((void *) basepointer)+i+1012);
				accessptr(((void *) basepointer)+i+1013);
				accessptr(((void *) basepointer)+i+1014);
				accessptr(((void *) basepointer)+i+1015);
				accessptr(((void *) basepointer)+i+1016);
				accessptr(((void *) basepointer)+i+1017);
				accessptr(((void *) basepointer)+i+1018);
				accessptr(((void *) basepointer)+i+1019);
				accessptr(((void *) basepointer)+i+1020);
				accessptr(((void *) basepointer)+i+1021);
				accessptr(((void *) basepointer)+i+1022);
				accessptr(((void *) basepointer)+i+1023);
				i+=1024;
			}
		}
		averageaccestime = (getcurrenttsc() - start) / (maxruns*(analyzedsize));
		analysis[idxanalyzed] = averageaccestime;
		//printf("\nCache with size: %d | Average Time: %d\n",size,averageaccestime);
	}

#endif
	return idxanalyzed;
}


//Test L1,LLC and RAM cycles of hits
void TWO_evaluate_l1_llc_ram() {
	// 6 WAYS | 64 SETS | 64 BYTES(cacheline)
	unsigned int l1size = 6 * 64 * 64;
	// 16 WAYS | 1024 SETS | 64 BYTES(cacheline)
	unsigned int llcsize = 16 * 1024 * 64;
	// Size of evaluation array(where the cycles will be stores)
	unsigned int evaluationsize = (l1size/2) + (l1size*(2/3)) + (l1size+1) + (llcsize/2) + (llcsize-1) + (llcsize+1) + (llcsize*2) + (llcsize*3);
	// Allocate evaluation array(where the cycles will be stores)
	unsigned int *evaluation = mmap(0, evaluationsize * sizeof(unsigned int),
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// File name
	const char * dstfilename = concat(VARIATION_ANALYSIS_DATA_DIRECTORY,
			"l1_llc_ram_evaluation.data");

	int analysedsize = 0;
	int increment = 1;
	int maxruns = 100;
	int sizeofevaluation = 2;


	// Obtain cycles for the L1C/2
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(l1size/2, l1size/2, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the L1C*2/3
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation((l1size*0.6), (l1size*0.6), maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the L1C+1
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(l1size+1, l1size+1, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the LLC/2
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize/2, llcsize/2, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the LLC-1
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize-1, llcsize-1, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the LLC+1
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize+1, llcsize+1, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the 2xLLC
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize*2, llcsize*2, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);
	// Obtain cycles for the 2xLLC
	analysedsize = depois_de_email_19_06_2017_TWO_hitevaluation(llcsize*3, llcsize*3, maxruns, increment, sizeofevaluation+analysedsize, evaluation, analysedsize);

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

