//Macro per la circular shift
#define circular_shift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

/* 
 *  Struttura che conterrà le informazioni riguardo
 *  le operazioni di hashing.
 */
typedef struct sha1_struct

{
    unsigned block_digest[5]; // i 5 blocchi che formeranno l'output 

    unsigned low_length;        //La lunghezza del messaggio in bit
    unsigned high_length;       

    unsigned char block_message[64]; //blocchi dei messaggi da 512 bit
    int index_block;    // Indice dell'array di block_message 

    int isComputed;               //variabile che indica se il digest è stato calcolato
    int isCorrupted;              // variabile che indica se il calcolo del digest sia stato interrotto 
} sha1_struct
;


 
void sha1_init(sha1_struct *sha1);
int sha1_result(sha1_struct *sha1);
void sha1_input( sha1_struct *sha1,const unsigned char *message_array,unsigned length);

