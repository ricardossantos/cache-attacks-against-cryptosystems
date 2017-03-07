#ifndef CSVUTILS_H_
#define CSVUTILS_H_

//#include <string.h>

#include <fcntl.h> //open
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close

void arraytocsv(int threshold, char dstfilename[], long int *headers,unsigned int rowsize, unsigned int columnsize, unsigned int src[][columnsize]) {
	FILE* fptr;
	int i,j;

	fptr = fopen(dstfilename,"w");
	for (i = 0; i < rowsize; i++) {
		for (j = 0; j < columnsize; ++j) {
			if(src[i][j] == 1)
				fprintf(fptr, "%d,%u,0x%X\n", i, src[i][j], headers[j]);
		}
	}
	fclose(fptr);
}

#endif /* CSVUTILS_H_ */
