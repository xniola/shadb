**Introduzione**

Una funzione crittografica di hash associa a dati di lunghezza arbitraria (messaggio) una sequenza binaria di dimensione fissa. Questo valore di hash viene spesso indicato anche con il termine message digest (o digest). Una funzione crittografica di hash è progettata per essere unidirezionale (one-way), ossia una funzione difficile da invertire: l'unico modo per ricreare i dati di input dall'output di una funzione di hash ideale è quello di tentare una ricerca di forza-bruta di possibili input per vedere se vi è corrispondenza (match).

Con **SHA** (Secure Hash Algorithm) si indica una famiglia di funzioni crittografiche di hash sviluppate a partire dal 1993 dalla National Security Agency (NSA). Gli algoritmi della famiglia sono denominati SHA-1, SHA-224, SHA-256, SHA-384 e SHA-512: le ultime 4 varianti sono spesso indicate genericamente come SHA-2, per distinguerle dal primo. Il primo produce un digest del messaggio di soli 160 bit, mentre gli altri producono digest di lunghezza in bit pari al numero indicato nella loro sigla (ad esempio SHA-256 produce un digest di 256 bit). Nelle GNU Core Utilities sono disponibili i programmi (da shell) sha1sum, sha224sum, sha256sum, sha384sum e sha512sum che consentono di calcolare (e verificare) il digest associato ad un file. Una descrizione (con pseudocodice) degli algoritmi SHA sono disponibili ai seguenti link: link1, link2.


**Descrizione**

Nel progetto occorre sviluppare l'applicazione shadb che consente di archiviare i valori dei digest associati ai diversi file in un file apposito allo scopo di verificare se un dato file è già presente o meno nel proprio archivio. Le informazioni raccolte dal programma vengono salvate all'interno di un file la cui struttura è la seguente:

<absolutepathtoafile_1>\r\n
<shacode_1>\r\n
<digest_1>\r\n
...
<absolutepathtoafile_n>\r\n
<shacode_n>\r\n
<digest_n>\r\n
Il file di archivio contiene una sequenza (possibilmente vuota) delle informazioni raccolte durante le varie esecuzioni, dove per ogni file viene memorizzato:

il path assoluto al file (<absolutepathtoafile_n>);
la funzione SHA usata per calcolare il digest (<shacode_n> che può assumere i valori SHA1, SHA224, SHA256, SHA384, o SHA512);
il valore del digest associato al file (<digest_n>).
Aggiunta di Informazioni
Per aggiungere informazioni al repository, occorrerà invocare shadb con i seguenti parametri:

shadb [--dbfile|-d <dbfile>] add [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtoafile> 
il parametro (opzionale) <dbfile> indica il file dove viene salvato il repository. Se omesso viene utilizzato il file sahdb.out. A seguito di questa invocazione il programma:

Calcolerà il digest associato al contenuto del file <pathtoafile> usando l'algoritmo passato come parametro (se omesso, verrà usato SHA1);
Se non sono presenti altri file nell'archivio con il medesimo valore di hash l'informazione viene aggiunta nel repository;
Se un file è già presente nel repository viene stampato a video un messaggio di errore (inviato su stderr).
E' importante osservare che il parametro <pathtoafile> può essere un path relativo, mentre quello salvato nel repository deve essere un path assoluto.

**Esempio**
  
Consideriamo ad esempio il file lorem.txt accessibile con path assoluto /home/utente/lorem.txt il cui contenuto è il seguente:

Lorem ipsum dolor sit amet, consectetur adipisci elit, sed do eiusmod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrum exercitationem ullamco laboriosam, nisi ut aliquid ex ea commodi consequatur. Duis aute irure reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint obcaecat cupiditat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
Supponiamo che che venga invocato da shell il programma shadb all'interno della directory /home/utente/ con i seguenti parametri:

shadb add SHA1 ./lorem.txt 
Ne file sahdb.out (che assumiamo non aver indicizzato nessun file con analogo contenuto) verrà aggiunta la seguente porzione di dati:

/home/utente/loretm.txt\r\n
SHA1\r\n
e30e23b314c61b150ff5202d5aa30f87911893d1\r\n
Ricerca
Per verificare se un file è già presente nel repository occorre invocare shadb con i seguenti parametri:

shadb [--dbfile|-d <dbfile>] find [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtoafile> 
Anche in questo caso i parametri opzionali avranno come valore di default sahdb.out (per il file del repository) e SHA1 per l'algoritmo di codifica. Una volta invocato il programma:

Calcolerà il digest associato al file <pathtoafile> usando l'algoritmo passato come parametro (se omesso, verrà usato SHA1);
Viene stampato sullo standard output il file assoluto del file con il medesimo hash calcolato (se esiste);
Se tale file non esiste, viene stampato sullo standard error un messaggio di errore.
