#ifndef CACHETECHNIQUES_H_
#define CACHETECHNIQUES_H_

#include "assemblyinstructions.h"

unsigned long long reload(void* addr){
	unsigned long long start = mfence_rdtsc();
	movl(addr);
	unsigned long long end = mfence_rdtsc();
	return end-start;
}

unsigned long long reloadandflush(void* addr){
	unsigned long long start = mfence_rdtsc();
	movl(addr);
	unsigned long long end = mfence_rdtsc();
	clflush(addr);
	return end-start;
}

#endif /* CACHETECHNIQUES_H_ */
