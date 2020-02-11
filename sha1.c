/*  
    produce un messaggio(digest) di 160 bit per un determinato tipo di dato.
    Teoricamente è molto improbabile che due messaggi produrranno lo stesso messaggio
    di digest.
    Lunghezza massima del messaggio: 2^64 bits
*/

#include "sha1.h"

/*  
 * Funzione che calcola i prossimi 512 bits del messaggio
 * contenuto nel block_message       
 */
void message_block_process(sha1_struct *sha1)
{
    const unsigned K[] =            // Costanti definite in SHA1      
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int t;                  //usato nei for
    unsigned    temp;               //Valore della parola temporanea
    unsigned    W[80];              //Sequenza di parole
    unsigned    A, B, C, D, E;      // buffers per le parole

    
      //Inizializza le prime 16 parole nell'array W
    for(t = 0; t < 16; t++)
    {
        //Calcola il messaggio in blocchi successivi da 512 bits:
        W[t] = ((unsigned) sha1->block_message[t * 4]) << 24;
        W[t] |= ((unsigned) sha1->block_message[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) sha1->block_message[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) sha1->block_message[t * 4 + 3]);
    }

    //Estendo le 16 parole da 32 bit in 8 parole da 32 bits:
    for(t = 16; t < 80; t++)
    {
       W[t] = circular_shift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    //Inizializzo il valore hash per questi blocchi:
    A = sha1->block_digest[0];
    B = sha1->block_digest[1];
    C = sha1->block_digest[2];
    D = sha1->block_digest[3];
    E = sha1->block_digest[4];


    //MAIN LOOP

    /*
        temp = (a leftrotate 5) + f + e + k + w[i]
        e = d
        d = c
        c = b leftrotate 30
        b = a
        a = temp
    */
    for(t = 0; t < 20; t++)
    {
        temp =  circular_shift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = circular_shift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = circular_shift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = circular_shift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = circular_shift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = circular_shift(30,B);
        B = A;
        A = temp;
    }

    /*
    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
    */
    sha1->block_digest[0] = (sha1->block_digest[0] + A) & 0xFFFFFFFF;
    sha1->block_digest[1] = (sha1->block_digest[1] + B) & 0xFFFFFFFF;
    sha1->block_digest[2] = (sha1->block_digest[2] + C) & 0xFFFFFFFF;
    sha1->block_digest[3] = (sha1->block_digest[3] + D) & 0xFFFFFFFF;
    sha1->block_digest[4] = (sha1->block_digest[4] + E) & 0xFFFFFFFF;

    sha1->index_block = 0;
}





/*  
 *  Il messaggio deve essere imbottito in una lunghezza pari a 512 bits.
 *  Il primo bit deve essere pari a 1, gli ultimi 64 rappresentano la lunghezza
 *  del messaggio originale. Tutti i bit intermedi devono essere 0.
 *  Questa funzione riempie il messaggio secondo tali regole riempiendo
 *  l'array di message_block. Invoca inoltre la funzione message_block_process.
 *  Quando ritorna si può assumere che il digest sia stato calcolato(isComputed).
 *
 *  Parametro: sha1 , la struttura da imbottire.
 */
void sha1_imbottitura(sha1_struct *sha1)
{
    /*
        Verifica se il message_block attule sia troppo piccolo per 
        contenere l'imbottitura iniziale. Se è troppo piccolo, allora
        imbottiamo il blocco, lo processiamo, e poi lo si continua ad 
        imbottire in un secondo blocco
     */
    if (sha1->index_block > 55)
    {
        sha1->block_message[sha1->index_block++] = 0x80;
        while(sha1->index_block < 64)
        {
            sha1->block_message[sha1->index_block++] = 0; //imbottiamo di 0
        }

        message_block_process(sha1); //processiamo tale blocco

        while(sha1->index_block < 56)
        {
            sha1->block_message[sha1->index_block++] = 0;
        }
    }
    else
    {
        sha1->block_message[sha1->index_block++] = 0x80;
        while(sha1->index_block < 56)
        {
            sha1->block_message[sha1->index_block++] = 0;
        }
    }

    /*
     *  Memorizza la lunghezza del messaggio
     */
    sha1->block_message[56] = (sha1->high_length >> 24) & 0xFF;
    sha1->block_message[57] = (sha1->high_length >> 16) & 0xFF;
    sha1->block_message[58] = (sha1->high_length >> 8) & 0xFF;
    sha1->block_message[59] = (sha1->high_length) & 0xFF;
    sha1->block_message[60] = (sha1->low_length >> 24) & 0xFF;
    sha1->block_message[61] = (sha1->low_length >> 16) & 0xFF;
    sha1->block_message[62] = (sha1->low_length >> 8) & 0xFF;
    sha1->block_message[63] = (sha1->low_length) & 0xFF;

    message_block_process(sha1);
}



/*  
 *  Inizializza la struttura per poter
 *  calcolare un nuovo messaggio(digest)
 */
void sha1_init(sha1_struct *sha1)
{
    sha1->low_length             = 0;
    sha1->high_length            = 0;
    sha1->index_block    = 0;

    //Inizializzo le costanti
    sha1->block_digest[0]      = 0x67452301;
    sha1->block_digest[1]      = 0xEFCDAB89;
    sha1->block_digest[2]      = 0x98BADCFE;
    sha1->block_digest[3]      = 0x10325476;
    sha1->block_digest[4]      = 0xC3D2E1F0;

    sha1->isComputed   = 0;
    sha1->isCorrupted  = 0;
}

/*  
 *  Funzione che ritorna il digest del messaggio da 160 bit nel
 *  block_digest con la struttura fornita.
 *  Prende come parametro la struttura da usare per calcolare
 *  l'hash.
 *  Ritorna 1 se è stato calcolato correttamente, 0 altrimenti. 
 */
int sha1_result(sha1_struct *sha1)
{

    if (sha1->isCorrupted)
        return 0;
    

    if (!sha1->isComputed)
    {
        sha1_imbottitura(sha1);
        sha1->isComputed = 1;
    }

    return 1;
}

/* 
 *  La funzione accetta un array di 8 bits come prossima 
 *  porzione del messaggio.
 *  Prende come parametro: sha1, la struttura da aggiornare.
 *  message_array: la prossima porzione del messaggio
 *  length: la lunghezza del messaggio
 */
void sha1_input( sha1_struct *sha1,const unsigned char *message_array,unsigned length)
{
    if (!length)
        return;

    if (sha1->isComputed || sha1->isCorrupted)
    {
        sha1->isCorrupted = 1;
        return;
    }

    while(length-- && !sha1->isCorrupted)
    {
        sha1->block_message[sha1->index_block++] = (*message_array & 0xFF); //lo forza a 8 bit

        sha1->low_length += 8; //aggiungiamo 8 bits poiche abbiamo aggiunto message_array

        // Lo forza a 32 bits
        sha1->low_length &= 0xFFFFFFFF;

        if (sha1->low_length == 0)
        {
            sha1->high_length++;

            // Lo forza a 32 bits
            sha1->high_length &= 0xFFFFFFFF;

            if (sha1->high_length == 0)
                sha1->isCorrupted = 1; //Il messaggio è troppo lungo
            
        }

        if (sha1->index_block == 64)    
           message_block_process(sha1); //lunghezza giusta
        
        message_array++;
    }
}

