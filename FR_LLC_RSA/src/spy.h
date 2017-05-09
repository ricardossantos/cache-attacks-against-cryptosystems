/*
 * spy.h
 *
 *  Created on: 08/05/2017
 *      Author: Ricardo-PC
 */

#ifndef SPY_H_
#define SPY_H_

#define MAX_ADDRS_TO_MONITOR 10

#define MAX_TIMES_TO_MONITOR_EACH_ADDRS 300000

unsigned long obtainthreshold(int histogramsize, int histogramscale) ;

long int getaddrstomonitor(const char* exeaddrsfilename, long int* out_addrs) ;

int setcoreaffinity(int core_id) ;

void delayloop(size_t cycles) ;

int isvictimactive(unsigned int *analysis, int nr_addrs, int threshold) ;

int missedvictimactivity(unsigned long long startcycles) ;

void analysealladdrs(unsigned int *out_analysis, unsigned long ptr_offset,
		long int *exe_addrs, int nr_addrs, int threshold) ;

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
