#ifndef FILEUTILS_H_
#define FILEUTILS_H_

//#include <string.h>

#include <fcntl.h> //open
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> //close

void arraytodatafile(char dstfilename[], unsigned short int * src,
		unsigned int rowsize, unsigned int columnsize) {
	FILE *fptr;
	int i, j;

	fptr = fopen(dstfilename, "w");
	fprintf(fptr, "%d", rowsize);
	for (i = 0; i < columnsize; i++) {
		fprintf(fptr, " %d", i);
	}
	fprintf(fptr, "\n");
	for (i = 0; i < rowsize; i++) {
		fprintf(fptr, "%d", i);
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, "%d ", *src);
			if(j == columnsize-1)
				fprintf(fptr, "%d", *src);
			src++;
		}
		fprintf(fptr, "\n");
	}
	fprintf(fptr, "%s\n", "e");
}

void arraytodatafilewithoutlabels(char dstfilename[], unsigned short int * src,
		unsigned int rowsize, unsigned int columnsize) {
	FILE *fptr;
	int i, j;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; i++) {
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, "%d ", *src);
			if(j == columnsize-1)
				fprintf(fptr, "%d", *src);
			src++;
		}
		fprintf(fptr, "\n");
	}
	fprintf(fptr, "%s\n", "e");
}

void biarraytocsvwithhexheaders(char dstfilename[], long int *headers,
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

void biarraytocsvwithstrheaders(char dstfilename[], char **headers,
		unsigned int rowsize, unsigned int columnsize,
		unsigned int src[][columnsize]) {
	FILE* fptr;
	int i, j;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; i++) {
		for (j = 0; j < columnsize; ++j) {
			fprintf(fptr, "%d,%u,%s\n", i, src[i][j], headers[j]);
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

#endif /* FILEUTILS_H_ */
