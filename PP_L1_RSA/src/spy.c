#include <stdio.h>
#include <string.h>

#include "../../Utils/assemblyinstructions.h"
#include "../../Utils/cachetechniques.h"
#include "../../Utils/csvutils.h"

#define PAGE_SIZE 4096
#define L1D_CACHE_NUMBER_OF_SETS 64
#define L1D_CACHE_NUMBER_OF_WAYS 6
#define L1D_CACHE_LINE_NUMBER_OF_BYTES 64
#define L1D_CACHE_SIZE_OF_WAY L1D_CACHE_LINE_NUMBER_OF_BYTES*L1D_CACHE_NUMBER_OF_SETS

#define L1D_CACHE_LINE_BASE_ADDR(baseptr,set,way) (void*) (((unsigned long) baseptr) + (set * L1D_CACHE_LINE_NUMBER_OF_BYTES) + (way * L1D_CACHE_SIZE_OF_WAY))
#define PREVIOUS_CACHE_LINE_PTR_ADDR(baseptr,set,way) (void*) (((unsigned long) baseptr) + (set * L1D_CACHE_LINE_NUMBER_OF_BYTES) + (way * L1D_CACHE_SIZE_OF_WAY) + sizeof(void *))

#define ANALYSIS_CSV_FILENAME "/home/root/thesis-code/static_analysis.csv"

//Silvermont:
//L1 D-Cache is a 24KB, 6 way associative with 64B lines.
//			375 cache lines. 62.5 lines within each set (the same as number of sets.
//			Number of sets is 375/6
//L1 I-Cache is a 32KB, 8 way associative with 64B lines.
//			500 cache lines. 62.5 lines within each set.
//L2 Cache is 1MB, 16 associative and 32B/cycle bandwidth shared by the 2 cores.

void monitorentirecache(unsigned int l1d_cachesize,
		unsigned int cache_lines_number, unsigned int cache_line_size_in_bytes) {
	char * l1d_basepointer = malloc(l1d_cachesize);
	memset(l1d_basepointer, 0, l1d_cachesize);
	unsigned int l1d_analysis[cache_lines_number][cache_line_size_in_bytes];
	int i = 0, line_byte = 0;
	unsigned long long start, start1;
	start1 = getcurrenttsc();
	for (i = 0; i < l1d_cachesize;
			++i, i % cache_line_size_in_bytes == 0 ? ++line_byte : line_byte) {
		start = getcurrenttsc();
		l1d_basepointer[line_byte];
		l1d_analysis[line_byte][i % cache_line_size_in_bytes] = getcurrenttsc()
				- start;
	}
	printf("TSC of the operation: %d\n", getcurrenttsc() - start1);
	biarraytocsv(ANALYSIS_CSV_FILENAME, cache_lines_number,
	CACHELINESIZEINBYTES, l1d_analysis);
}


typedef struct l1dcache {
	void *basepointer;
	void *nextline;
	void *prevline;
	unsigned int measurement;
}*l1dcache_t;

l1dcache_t preparel1cachestruct() {
	int set, way;
	l1dcache_t l1 = (l1dcache_t) malloc(sizeof(l1dcache_t));
	l1->basepointer = mmap(0, PAGE_SIZE * L1D_CACHE_NUMBER_OF_WAYS,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	l1->nextline = NULL;
	l1->prevline = NULL;
	for (set = 0; set < L1D_CACHE_NUMBER_OF_SETS; ++set) {
		for (way = 0; way < L1D_CACHE_NUMBER_OF_WAYS - 1; way++) {
			// (set,way)->nextline = &(set,way+1)
			(*(void **) (L1D_CACHE_LINE_BASE_PTR(l1->basepointer, set, way))) =
					L1D_CACHE_LINE_BASE_PTR(l1->basepointer, set, way + 1);
			// (set,way+1)->previousline = &(set,way)
			(*(void **) (PREVIOUS_CACHE_LINE_PTR_ADDR(l1->basepointer, set,
					way+1))) = PREVIOUS_CACHE_LINE_PTR_ADDR(l1->basepointer,
					set, way);
		}
	}
	return l1;
}
/* END V1 */

void analysel1dcache(l1dcache_t l1dcache){
	int i;
	for(i=0; i < )
}

int main() {
	/* BEGIN V1 */
	//1st state
	l1dcache_t l1dcache = preparel1cachestruct();

	//2nd state
	accessentirel1dcache(l1dcache);

	//3rd state
	analysel1dcache(l1dcache, MAX_ELEMENTS_TO_MONITOR);

	/* END V1 */
	unsigned int l1d_analysis[cache_lines_number][CACHELINESIZEINBYTES];
	int i = 0, line_byte = 0;
	unsigned long long start, start1;
	start1 = getcurrenttsc();
	for (i = 0; i < l1d_cachesize;
			++i, i % CACHELINESIZEINBYTES == 0 ? ++line_byte : line_byte) {
		start = getcurrenttsc();
		l1d_basepointer[line_byte];
		l1d_analysis[line_byte][i % CACHELINESIZEINBYTES] = getcurrenttsc()
				- start;
	}
	printf("TSC of the operation: %d\n", getcurrenttsc() - start1);
	biarraytocsv(ANALYSIS_CSV_FILENAME, cache_lines_number,
	CACHELINESIZEINBYTES, l1d_analysis);
	return 0;
}
