#include "shadb.h"


static file_info info;

/*Esegue l'operazione di find
-repository: è il file di output dove cercare le informazioni
-path: è il percorso del file da criptare
-shacode: è la stringa che identifica l'hash da utilizzare
return 0 se il file non è stato trovato, 1 altrimenti
*/
file_info* find(char* repository, char* path,const char* shacode){

    //file_info info = malloc(sizeof(file_info));
    

/*
N.B. poiché molti file system in Linux supportano hard links, 
     ogni directory specifica può avere un numero di percorsi assoluti diversi.
*/
    char actualpath[sizeof(path)*sizeof(char)]; //path relativo
    char* buf = realpath(path, actualpath); //path assoluto
    
    char* file_text = read_file(buf); //il testo del file di input
    char *repository_text = read_file(repository); //il testo del file dove cercare

    if(strlen(repository_text) < 1) //il repository è vuoto
        return NULL;

    unsigned char message[SHA512_DIGEST_SIZE]; //usato per gli sha2

   char buffer[strlen(buf)*sizeof(char)];
   info.path = strcpy(buffer,buf);

    if (strcmp(shacode, "SHA1") == 0){     

        info.shacode = "SHA1";
       
        //5 pezzi da 32
        char digest0[32];
        char digest1[32];
        char digest2[32];
        char digest3[32];
        char digest4[32];
        char digest[160];

            sha1_struct sha;
            sha1_init(&sha);
            sha1_input(&sha,file_text,strlen(file_text));

            if(!sha1_result(&sha)){
                fprintf(stderr,"Errore");
                free(repository_text);
                return NULL;
            } 
        sprintf(digest0,"%x",sha.block_digest[0]);   
        sprintf(digest1,"%x",sha.block_digest[1]);
        sprintf(digest2,"%x",sha.block_digest[2]);
        sprintf(digest3,"%x",sha.block_digest[3]);
        sprintf(digest4,"%x",sha.block_digest[4]);
        sprintf(digest,"%s%s%s%s%s",digest0,digest1,digest2,digest3,digest4);
        info.digest = digest;
    
        /*Cerco se nel repository è presente il path con relativo digest*/
        char* to_search = strcat(info.path,"\r\n");
        char* to_search2 = strcat(to_search,"SHA1\r\n");
        char* to_search3 = strcat(to_search2,digest);   
          

        if(strstr(repository_text,to_search3) == NULL)
            return NULL;
        
        else
            return &info;
    }

    else if(strcmp(shacode, "SHA224") == 0){
        char text[10000];
        strcpy(text,repository_text);
        
        info.shacode = "SHA224";

        sha224((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA224_DIGEST_SIZE);//ottengo il digest
        
        char* to_search = strcat(info.path,"\r\n");
        char* to_search2 = strcat(to_search,"SHA224\r\n");


        char buff[224];
        strcpy(buff, info.digest);

        char* to_search3 = strcat(to_search2,buff); 
        char* result224 = strstr(text,to_search3);

        if(result224 == NULL)
            return NULL;

        else
            return &info;
    }
    else if(strcmp(shacode,"SHA256") == 0){
        char text[10000];
        strcpy(text,repository_text);
        
        info.shacode = "SHA256";

        sha256((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA256_DIGEST_SIZE);//ottengo il digest
        
        char* to_search = strcat(info.path,"\r\n");
        char* to_search2 = strcat(to_search,"SHA256\r\n");


        char buff[256];
        strcpy(buff, info.digest);

        char* to_search3 = strcat(to_search2,buff); 
        char* result224 = strstr(text,to_search3);

        if(result224 == NULL)
            return NULL;

        else
            return &info;
        
    }
    else if(strcmp(shacode,"SHA384") == 0){
         char text[10000];
        strcpy(text,repository_text);
        
        info.shacode = "SHA384";

        sha384((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA384_DIGEST_SIZE);//ottengo il digest
        
        char* to_search = strcat(info.path,"\r\n");
        char* to_search2 = strcat(to_search,"SHA384\r\n");


        char buff[384];
        strcpy(buff, info.digest);

        char* to_search3 = strcat(to_search2,buff); 
        char* result224 = strstr(text,to_search3);

        if(result224 == NULL)
            return NULL;

        else
            return &info;
    }
    else if(strcmp(shacode,"SHA512") == 0){
        char text[10000];
        strcpy(text,repository_text);
        
        info.shacode = "SHA512";

        sha512((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA512_DIGEST_SIZE);//ottengo il digest
        
        char* to_search = strcat(info.path,"\r\n");
        char* to_search2 = strcat(to_search,"SHA512\r\n");


        char buff[512];
        strcpy(buff, info.digest);

        char* to_search3 = strcat(to_search2,buff); 
        char* result224 = strstr(text,to_search3);

        if(result224 == NULL)
            return NULL;

        else
            return &info;
    }
    else{
        SYNTAX_ERROR;
     
        return NULL;
    }
}

/*
return 0 se il file è già presente, 1 se il file viene aggiunto con successo
*/
int add(char* repository,char* path, const char* shacode){
    //file_info info_ref = info;
    if(find(repository,path,shacode) != NULL){
        fprintf(stderr,"Il file è già presente nell'archivio\n");
        return 0;
    }

    char actualpath[sizeof(path)*sizeof(char)]; //path relativo
    char *buf; //buffer dove viene memorizzato il path assoluto
    buf = realpath(path, actualpath); //path assoluto

    char* file_text;
    file_text = read_file(buf); //il testo del file di input

    unsigned char message[SHA512_DIGEST_SIZE]; //usato per gli sha2
  
    char buffer[strlen(buf)*sizeof(char)];
    info.path = strcpy(buffer,buf);

    if(strcmp(shacode, "SHA1") == 0){
        info.shacode = "SHA1";
            sha1_struct sha;
            sha1_init(&sha);
            sha1_input(&sha,file_text,strlen(file_text));

            if(!sha1_result(&sha)){
                fprintf(stderr,"Errore");
                return 0;
            }
             //5 pezzi da 32
        char digest0[32];
        char digest1[32];
        char digest2[32];
        char digest3[32];
        char digest4[32];
        char digest[160]; 

        sprintf(digest0,"%x",sha.block_digest[0]);   
        sprintf(digest1,"%x",sha.block_digest[1]);
        sprintf(digest2,"%x",sha.block_digest[2]);  
        sprintf(digest3,"%x",sha.block_digest[3]);        
        sprintf(digest4,"%x",sha.block_digest[4]);
        sprintf(digest,"%s%s%s%s%s",digest0,digest1,digest2,digest3,digest4);

        info.digest = digest;

        write_out_file(repository,&info);
       
        return 1;
    }
    else if(strcmp(shacode,"SHA224") == 0){
        info.shacode = "SHA224";

        sha224((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA224_DIGEST_SIZE);//ottengo il digest
        write_out_file(repository,&info);
        
        return 1;
    }
    else if(strcmp(shacode,"SHA256") == 0){
        info.shacode = "SHA256";

        sha256((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA256_DIGEST_SIZE);//ottengo il digest
        write_out_file(repository,&info);
        
        return 1;
    }
    else if(strcmp(shacode,"SHA384") == 0){
        info.shacode = "SHA384";

        sha384((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA384_DIGEST_SIZE);//ottengo il digest
        write_out_file(repository,&info);
       
        return 1;
    }
    else if(strcmp(shacode,"SHA512") == 0){
        info.shacode = "SHA512";

        sha512((const unsigned char*)file_text,strlen(file_text),message);
        info.digest = get_digest(message,SHA512_DIGEST_SIZE);//ottengo il digest
        write_out_file(repository,&info);
        
        return 1;
    }
    else{  
        SYNTAX_ERROR;
        return 0;
    }
}

void parse_argc3(char* argv[]){

    if(strcmp(argv[1],"add") == 0)
        add(DEFAULT_OUTPUT_FILE,argv[2],DEFAULT_SHA_OPTION);    

    else if(strcmp(argv[1],"find") == 0){
        file_info* info_ref = find(DEFAULT_OUTPUT_FILE,argv[2],DEFAULT_SHA_OPTION);
            if(&info == NULL)
                fprintf(stderr,"Il file non è presente nel repository\n");
            else{
                printf("%s\r\n",info_ref->path);
                fflush(stdout);
            }
    }
    else SYNTAX_ERROR;
}

void parse_argc4(char* argv[]){
    

    char* p = argv[1]; // --dbfile
    char* output_file = p+2; // dbfile  

    if(strcmp(argv[1],"add") == 0)
        add(DEFAULT_OUTPUT_FILE,argv[3],argv[2]);

    else if(strcmp(argv[1],"find") == 0){
      file_info* info_refer = find(DEFAULT_OUTPUT_FILE,argv[3],argv[2]);
        if(&info == NULL)
           fprintf(stderr,"Il file non è presente nel repository\n");               
        else{
            printf("%s\r\n",info_refer->path);
            fflush(stdout);
        }
   }
    else if(strcmp(argv[2],"add") == 0)
        add(output_file,argv[3],DEFAULT_SHA_OPTION);

    else if(strcmp(argv[2],"find") == 0){
       file_info* info_ref = find(output_file,argv[3],DEFAULT_SHA_OPTION);
            if(&info == NULL)
                fprintf(stderr,"Il file non è presente nel repository\n");
            else{
                printf("%s\r\n",info_ref->path);
                fflush(stdout);
            }
    }
    else SYNTAX_ERROR;
}

void parse_argc5(char* argv[]){
    file_info *info;

    char* p = argv[1]; //--dbfile
    char* output_file = p+2; // dbfile

    if(strcmp(argv[2],"add") == 0)
        add(output_file,argv[4],argv[3]);

    else if(strcmp(argv[2],"find") == 0){
        info = find(output_file,argv[4],argv[3]);
            if(info == NULL)
                fprintf(stderr,"Il file non è presente nel repository\n");
            else{
                printf("%s\r\n",info->path);
                fflush(stdout);
            }
    }

    else if(strcmp(argv[3],"add") == 0)
        add(argv[2],argv[4],DEFAULT_SHA_OPTION);

    else if(strcmp(argv[3],"find") == 0){
       info = find(argv[2],argv[4],DEFAULT_SHA_OPTION);
       if(info == NULL)
            fprintf(stderr,"Il file non è presente nel repository\n");
        else{
            printf("%s\r\n",info->path);
            fflush(stdout);
        }
    }
    else SYNTAX_ERROR;
}

void parse_argc6(char* argv[]){
    file_info* info;

    if(strcmp(argv[3],"add") == 0)
        add(argv[2],argv[5],argv[4]);

    else if(strcmp(argv[3],"find") == 0){
        info = find(argv[2],argv[5],argv[4]);
        if(info == NULL)
                fprintf(stderr,"Il file non è presente nel repository\n");
        else{
            printf("%s\r\n",info->path);
            fflush(stdout);
        }
    }
    else SYNTAX_ERROR;
}

void parse_arguments(int argc, char* argv[]){
    if(argc == 3)
       parse_argc3(argv);
    
    else if(argc == 4)
        parse_argc4(argv);
    
    else if(argc == 5)
        parse_argc5(argv);
    
    else if(argc == 6)
        parse_argc6(argv);

    else SYNTAX_ERROR;
}



int main(int argc, char *argv[]){
    parse_arguments(argc,argv);
}