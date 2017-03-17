#ifndef ASSEMBLYINSTRUCTIONS_H_
#define ASSEMBLYINSTRUCTIONS_H_

//i386 systems
//https://www.mcs.anl.gov/~kazutomo/rdtsc.html

//- threshold
unsigned long long mfence_lfence_rdtsc() {
	volatile unsigned long long tsc;
	asm volatile("mfence");
	asm volatile("lfence");
	asm volatile("rdtsc" : "=A" (tsc));
	asm volatile("lfence");
	return tsc;
}

unsigned long long lfence_rdtsc() {
	volatile unsigned long long tsc;
	asm volatile("lfence");
	asm volatile("rdtsc" : "=A" (tsc));
	asm volatile("lfence");
	return tsc;
}

//- threshold
unsigned long long rdtscp() {
	volatile unsigned int low, high;
	asm volatile (" mfence \n"
			" lfence \n"
			" rdtscp \n": "=a" (low), "=d" (high) :: "ecx");
	return (((unsigned long long) high) << 32) | low;
}

void movl(void* addr) {
	asm volatile("movl (%0), %%eax\n"
			:
			: "r" (addr)
			: "%eax");
}

void clflush(void* addr) {
	asm volatile("clflush 0(%0)\n"
			:
			: "r" (addr)
			: );
}

unsigned int time_movl_clflush(void* addr) {
	volatile unsigned int time;
	asm volatile(
			" mfence \n"
			" lfence \n"
			" rdtscp \n"
			" mov %%eax, %%esi \n"
			" mov (%1), %%eax \n"
			" rdtscp \n"
			" sub %%esi, %%eax \n"
			" clflush 0(%1) \n"
			: "=&a" (time)
			: "r" (addr)
			: "%esi", "%edx", "ecx");
	return time;
}

unsigned int time_movl(void* addr) {
	volatile unsigned int time;
	asm volatile(
			" mfence \n"
			" lfence \n"
			" rdtscp \n"
			" mov %%eax, %%esi \n"
			" mov (%1), %%eax \n"
			" rdtscp \n"
			" sub %%esi, %%eax \n"
			: "=&a" (time)
			: "r" (addr)
			: "%esi", "%edx", "ecx");
	return time;
}

#endif /* ASSEMBLYINSTRUCTIONS_H_ */
