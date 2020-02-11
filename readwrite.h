#include <stdio.h>
#include <stdlib.h>

#include "fileInfo.h"

/*Legge il path di input*/
char* read_file(const char *path);

/*Scrive sul file di output*/
void write_out_file(char *repository,file_info* info);