#include "fileInfo.h"

void init_struct(struct file_info* info){
   info = malloc(sizeof(file_info));
   info->path = "";
   info->shacode = "";
   info->digest = "";
}