#ifndef CACHETECHNIQUES_H_
#define CACHETECHNIQUES_H_

#include "assemblyinstructions.h"

unsigned int reload(void* addr) {
//	size_t start = mfence_lfence_rdtsc();
//	movl(addr);
//	size_t end = lfence_rdtsc() - start;
//	return end;
	return time_movl(addr);
}

void flush(void* addr) {
	clflush(addr);
}

unsigned long long getcurrenttsc() {
	return rdtscp();
}

unsigned int reloadandflush(void* addr) {
//	size_t start = mfence_lfence_rdtsc();
//	movl(addr);
//	size_t end = lfence_rdtsc() - start;
//	clflush(addr);
//	size_t k;
//	for (k = 0; k < 5; ++k)
//		sched_yield();
//	return end;
	return time_movl_clflush(addr);
}

#endif /* CACHETECHNIQUES_H_ */
