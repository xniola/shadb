#include "readwrite.h"

/*Legge il file passato come parametro e ne ritorna il contenuto*/
char* read_file(const char *path){
    char *source = NULL;
    FILE *fp = fopen(path, "r");
        if (fp != NULL) {
            /* Vado alla fine del file */
             if (fseek(fp, 0L, SEEK_END) == 0) {
                /* Ottengo la dimensione del file */
                 long bufsize = ftell(fp);
        if (bufsize == -1) {
            fprintf(stderr,"Il file non esiste");
            exit(0);
        }

        /* Alloco un buffer dalla dimensione del file */
        source = malloc(sizeof(char) * (bufsize + 1));

        /*Ritorno all'inizio del file */
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            printf("Errore");
            exit(0);
         }

        /* Leggo l'intero file e lo metto in memoria */
        size_t newLen = fread(source, sizeof(char), bufsize, fp);
        if ( ferror( fp ) != 0 ) {
            fputs("Errore durante la lettura del file", stderr);
        } else {
            source[newLen++] = '\0';
        }
    }
    return source;
    fclose(fp);
}
}

/*Scrive sul file le informazioni passate come parametro(nodo)*/
void write_out_file(char *repository,file_info* info){
    FILE *fout = fopen(repository, "a"); // Apro il file in modalita append
      
    fprintf(fout, "%s\r\n", info->path);
    fprintf(fout, "%s\r\n", info->shacode);
    fprintf(fout, "%s\r\n", info->digest);
    fprintf(fout, "...\r\n");

    fclose(fout);
}