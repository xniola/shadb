#ifndef SHA2_H
#define SHA2_H

//Dimensioni dei digest delle varie funzioni sha in bytes
#define SHA224_DIGEST_SIZE ( 224 / 8)
#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA384_DIGEST_SIZE ( 384 / 8)
#define SHA512_DIGEST_SIZE ( 512 / 8)

//Dimensioni dei blocchi delle varie funzioni sha in bytes
#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE //sha384 lavora con la stessa dimensione dei blocchi di sha512
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE //sha224 lavora con la stessa dimensione dei blocchi di sha256

//Definisco i tipi delle lunghezze delle sha
#ifndef SHA2_TYPES
#define SHA2_TYPES
typedef unsigned char uint8; 
typedef unsigned int  uint32;
typedef unsigned long long uint64;
#endif

#include <stdlib.h>
#include <stdio.h>

//struttura di sha256 e sha224
typedef struct {
    unsigned int total_length;
    unsigned int len;
    unsigned char block[2 * SHA256_BLOCK_SIZE];
    uint32 h[8];
} sha256_struct;

//struttura di sha512 e sha384
typedef struct {
    unsigned int total_length;
    unsigned int len;
    unsigned char block[2 * SHA512_BLOCK_SIZE];
    uint64 h[8];
} sha512_struct;

typedef sha512_struct sha384_struct; //sha384 è una versione troncata di sha512
typedef sha256_struct sha224_struct; //sha224 è una versione troncata di sha256


/*Usa le funzioni interne sha224_init,sha224_process_block,sha224_result*/
void sha224(const unsigned char *message, unsigned int len,unsigned char *digest);

/*Usa le funzioni interne sha256_init, sha256_process-block,sha224_result*/
void sha256(const unsigned char *message, unsigned int len,unsigned char *digest);

/*Usa le funzioni interne sha384_init,sha384_process_block.sha384_result*/
void sha384(const unsigned char *message, unsigned int len,unsigned char *digest);

/*Usa le funzioni interne sha512_init,sha512_process-block,sha512_result*/
void sha512(const unsigned char *message, unsigned int len,unsigned char *digest);

/*Funzione che ritorna il digest finale*/
char* get_digest(unsigned char *digest,unsigned int digest_size);

#endif 