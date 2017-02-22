#ifndef ASSEMBLYINSTRUCTIONS_H_
#define ASSEMBLYINSTRUCTIONS_H_

//i386 systems
//https://www.mcs.anl.gov/~kazutomo/rdtsc.html

unsigned long rdtscp() {
	unsigned long low, high;
	asm volatile("rdtscp\n" : "=a"(low), "=d"(high));
	return low;
}

unsigned long long lfence_rdtsc() {
	unsigned long long tsc;
	asm volatile("lfence");
	asm volatile(".byte 0x0f, 0x31" : "=A" (tsc));
	asm volatile("lfence");
	return tsc;
}

unsigned long long mfence_rdtsc() {
	unsigned long long tsc;
	asm volatile("mfence");
	asm volatile(".byte 0x0f, 0x31" : "=A" (tsc));
	asm volatile("mfence");
	return tsc;
}

void movl(void* addr) {
	asm volatile("movl (%0), %%eax\n" :: "r" (addr): "eax");
}

void clflush(void* addr) {
	asm volatile("clflush (%0)\n" :: "r" (addr): "eax");
}

#endif /* ASSEMBLYINSTRUCTIONS_H_ */
