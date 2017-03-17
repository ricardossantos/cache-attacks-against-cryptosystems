#ifndef CSVUTILS_H_
#define CSVUTILS_H_

//#include <string.h>

#include <fcntl.h> //open
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> //close

void biarraytocsvwheaders(char dstfilename[], long int *headers,
		unsigned int rowsize, unsigned int columnsize,
		unsigned int src[][columnsize]) {
	FILE* fptr;
	int i, j;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; i++) {
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, "%d,%u,0x%X\n", i, src[i][j], headers[j]);
		}
	}
	fclose(fptr);
}

void biarraytocsv(char dstfilename[], unsigned int rowsize,
		unsigned int columnsize, unsigned int src[][columnsize]) {
	FILE* fptr;
	int i, j;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; i++) {
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, "%d,%u\n", i, src[i][j]);
		}
	}
	fclose(fptr);
}

void arraytocsv(char dstfilename[], unsigned int rowsize, unsigned int src[]) {
	FILE* fptr;
	int i;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; i++) {
		fprintf(fptr, "%d,%u\n", i, src[i]);
	}
	fclose(fptr);
}

#endif /* CSVUTILS_H_ */
