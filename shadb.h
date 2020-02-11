#include <string.h>
#include <stddef.h>

#include "sha1.h"
#include "sha2.h"
#include "readwrite.h"
#include "shadb.out"


#define DEFAULT_OUTPUT_FILE "shadb.out"
#define DEFAULT_SHA_OPTION "SHA1"
#define SYNTAX_ERROR fprintf(stderr,"Non hai rispettato la sinossi del programma:\r\nshadb [--dbfile|-d <dbfile>] add/find [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtoafile>\n")


/*Funzione che analizza gli argomenti passati a riga di comando*/
void parse_arguments(int argc, char* argv[]);