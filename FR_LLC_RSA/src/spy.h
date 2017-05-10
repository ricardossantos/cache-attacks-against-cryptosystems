#ifndef SPY_H_
#define SPY_H_

#define MAX_ADDRS_TO_MONITOR 10
#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

unsigned long obtainthreshold(int histogramsize, int histogramscale) ;

void missedalladdrs(unsigned int *out_analysis, unsigned long ptr_offset,
		long int *exe_addrs, int nr_addrs) ;

void obtainmaxtimesabovethreshold(unsigned int* numberoftimesabovethreshold,
		unsigned int threshold, unsigned int rowsize, unsigned int columnsize,
		unsigned int src[][columnsize]) ;

void obtaindparameternumberofbits(unsigned int threshold, unsigned int rowsize,
		unsigned int columnsize, unsigned int src[][columnsize],
		unsigned int out_numberofbits[columnsize]);

int analysecache(int delay, long int exe_addrs[MAX_ADDRS_TO_MONITOR],
		int nr_addrs,
		unsigned int analysis_array[MAX_TIMES_TO_MONITOR_EACH_ADDRS][nr_addrs]);

void autoobtaindelay();


#endif /* SPY_H_ */
