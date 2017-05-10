#include "../../Utils/src/cachetechniques.h"

#define MAX_ADDRS_TO_MONITOR 10
#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

unsigned long obtainthreshold(int histogramsize, int histogramscale) {
	const int MAX_RUNS = 4 * 1024 * 1024;
	const int PAGES_SIZE = 4096;
	const int MID_ARRAY = PAGES_SIZE / 2;
	void *array;
	unsigned int *hit_counts;
	hit_counts = calloc(histogramsize, sizeof(unsigned int));
	unsigned int *miss_counts;
	miss_counts = calloc(histogramsize, sizeof(unsigned int));

	int i;
	array = mmap(0, PAGES_SIZE, PROT_READ | PROT_WRITE,
	MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	reload(array + MID_ARRAY);
	sched_yield();
	//4MB
	for (i = 0; i < MAX_RUNS; ++i) {
		reload(array + MID_ARRAY);
		unsigned long time = timeflush(array + MID_ARRAY) / histogramscale;
		hit_counts[time > (histogramsize - 1) ? histogramsize - 1 : time]++;
		sched_yield();
	}

	for (i = 0; i < MAX_RUNS; ++i) {
		flush(array + MID_ARRAY);
		unsigned long time = timeflush(array + MID_ARRAY) / histogramscale;
		miss_counts[time > (histogramsize - 1) ? histogramsize - 1 : time]++;
		sched_yield();
	}
	unsigned int hitmax = 0;
	unsigned int missmax = 0;
	unsigned int hitmaxindex = 0;
	unsigned int missmaxindex = 0;
	unsigned int missminindex = 0;
	printf("TSC:           HITS           MISSES\n");
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
			allhits = 0, evictionrate = 0, hitsrate = 0;
	int maxhit = 0, maxmiss = 0, threshold = 0;
	maxhit = hitmaxindex * histogramscale;
	maxmiss = missmaxindex * histogramscale;
	threshold = maxmiss - (maxmiss - maxhit) / 2;

	for (i = 0; i < histogramsize; ++i) {
		if (miss_counts[i] > 0 && (i * histogramscale) > threshold) {
			++countcorrectmisses;
		}
		if (miss_counts[i] > 0) {
			++allmisses;
		}
		if (hit_counts[i] > 0 && (i * histogramscale) < threshold) {
			++countcorrecthits;
		}
		if (hit_counts[i] > 0) {
			++allhits;
		}
	}

	evictionrate = (countcorrectmisses / allmisses) * 100;
	hitsrate = (countcorrecthits / allhits) * 100;

	printf("\nMax Hit: %u\n", maxhit);
	printf("\nMax Miss: %u\n", maxmiss);
	printf("\nThreshold: %u\n", threshold);
	printf("\nHits Rate: %lf\%\n", hitsrate);
	printf("\nEviction Rate: %lf\%\n", evictionrate);

	return threshold;
}



int main()
{
	//Obtain threshold
	unsigned long threshold = obtainthreshold(300,5);

	long int exe_addrs[MAX_ADDRS_TO_MONITOR];
	int nr_addrs;

	//obtain the addrs to monitor
	nr_addrs = getaddrstomonitor(EXE_ADDRS_FILENAME, exe_addrs);

	unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs];


	return 0;
}
