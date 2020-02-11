#include <stdlib.h>

/* struct che definisce il formato di un singolo file */
typedef struct file_info
{
    char *path;
    char *shacode;
    char *digest;
}file_info;

void init_struct(struct file_info* info);