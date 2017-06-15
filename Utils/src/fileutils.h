#ifndef FILEUTILS_H_
#define FILEUTILS_H_

//#include <string.h>

#include <fcntl.h> //open
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> //close

char* concat(const char *s1, const char *s2) {
	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);
	char *result = malloc(len1 + len2 + 1); //+1 for the zero-terminator
	//in real code you would check for errors in malloc here
	memcpy(result, s1, len1);
	memcpy(result + len1, s2, len2 + 1);    //+1 to copy the null-terminator
	return result;
}

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
			if (j == columnsize - 1)
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
			if (j == columnsize - 1)
				fprintf(fptr, "%d", *src);
			src++;
		}
		fprintf(fptr, "\n");
	}
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

void twoarraystocsvwithstrheaders(char dstfilename[], char * headersrc1,
		char * headersrc2, int scale, unsigned int size, unsigned int *src1,
		unsigned int *src2) {
	FILE* fptr;
	int i;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < size; ++i) {
		fprintf(fptr, "%d,%u,%s\n", i * scale, src1[i], headersrc1);
		fprintf(fptr, "%d,%u,%s\n", i * scale, src2[i], headersrc2);
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

void arraytocsv(char dstfilename[], int scale, unsigned int rowsize, unsigned int src[]) {
	FILE* fptr;
	int i;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < rowsize; ++i) {
		fprintf(fptr, "%d,%u\n", i*scale, src[i]);
	}
	fclose(fptr);
}

typedef struct stats{
	float mean;
	float sdev;
	float cvar;
}stats_t;

void logsetsstatistic(char dstfilename[], float *value, unsigned int size){
	FILE* fptr;
	int i;

	fptr = fopen(dstfilename, "w");
	for (i = 0; i < size; i++) {

		fprintf(fptr, "%d,%f\n", i, value[i]);
	}
	fclose(fptr);
}

#endif /* FILEUTILS_H_ */
