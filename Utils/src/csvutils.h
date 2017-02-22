#ifndef CSVUTILS_H_
#define CSVUTILS_H_

#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close

void arraytocsv(char dstfilename[], long int *headers,unsigned int rowsize, unsigned int columnsize, unsigned long long src[][columnsize]) {
	FILE* fptr;
	int i,j;

	fptr = fopen(dstfilename,"w");
	fprintf(fptr, "%s", "Times");
	for (i = 0; i < columnsize; ++i) {
		fprintf(fptr, "%X", headers[i]);
	}
	fprintf(fptr, "\n");
	for (i = 0; i < rowsize; i++) {
		fprintf(fptr, "%d", i);
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, ",%llu", src[i][j]);
		}
		fprintf(fptr, "\n");
	}
	fclose(fptr);
}

#endif /* CSVUTILS_H_ */
