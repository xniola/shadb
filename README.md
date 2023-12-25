**Introduction**

A cryptographic hash function associates data of arbitrary length (message) with a binary sequence of fixed size. This hash value is also often referred to as a message digest (or digest). A cryptographic hash function is designed to be unidirectional (one-way), i.e., a function that is difficult to reverse: the only way to recreate the input data from the output of an ideal hash function is to attempt a force-brute search of possible inputs to see if there is a match (match).

**SHA** (Secure Hash Algorithm) refers to a family of cryptographic hash functions developed since 1993 by the National Security Agency (NSA). The algorithms in the family are referred to as SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512: the last 4 variants are often referred to generically as SHA-2, to distinguish them from the former. The former produces a message digest of only 160 bits, while the others produce digests of length in bits equal to the number indicated in their abbreviation (e.g. SHA-256 produces a 256-bit digest). Available in the GNU Core Utilities are the programs (from the shell) sha1sum, sha224sum, sha256sum, sha384sum, and sha512sum that allow you to calculate (and verify) the digest associated with a file. A description (with pseudocode) of the SHA algorithms are available at the following links: link1, link2.


**Description**

In the project, the shadb application needs to be developed to store the digest values associated with different files in a special file for the purpose of checking whether or not a given file is already present in its archive. The information collected by the program is stored within a file whose structure is as follows:

<absolutepathtoafile_1>\r\n
<shacode_1>\r\n
<digest_1>\r\n
...
<absolutepathtoafile_n>\r\n
<shacode_n>\r\n
<digest_n>\r\n

The archive file contains a sequence (possibly empty) of the information collected during the various runs, where for each file is stored:

the absolute path to the file (<absolutepathtoafile_n>);
the SHA function used to calculate the digest (<shacode_n> which can take the values SHA1, SHA224, SHA256, SHA384, or SHA512);
the digest value associated with the file (<digest_n>).
Adding Information
To add information to the repository, you will need to invoke shadb with the following parameters:

shadb [--dbfile|-d <dbfile>] add [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtoafile> 
the (optional) <dbfile> parameter indicates the file where the repository is saved. If omitted, the file sahdb.out is used. Following this invocation the program 
will calculate the digest associated with the contents of the <pathtoafile> file using the algorithm passed as a parameter (if omitted, SHA1 will be used);
If there are no other files in the repository with the same hash value the information is added to the repository;
If a file is already present in the repository an error message is printed on the screen (sent on stderr).
It is important to note that the <pathtoafile> parameter can be a relative path, while the one saved in the repository must be an absolute path.

**Example**
  
Consider, for example, the file lorem.txt accessed with absolute path /home/user/lorem.txt whose contents are as follows:

Lorem ipsum dolor sit amet, consectetur adipisci elit, sed do eiusmod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrum exercitationem ullamco laboriosam, nisi ut aliquid ex ea commodi consequatur. Duis aute irure reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint obcaecat cupiditat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
Suppose that the shadb program within the /home/user/ directory is invoked from the shell with the following parameters:

shadb add SHA1 ./lorem.txt 
The following portion of data will be added to the sahdb.out file (which we assume has no indexed file with similar content):

/home/user/loretm.txt\r\n
SHA1\r\n
e30e23b314c61b150ff5202d5aa30f87911893d1\r\n

Search
To check whether a file is already in the repository, shadb must be invoked with the following parameters:

shadb [--dbfile|-d <dbfile>] find [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtoafile>. 
Again, the optional parameters will default to sahdb.out (for the repository file) and SHA1 for the encryption algorithm. Once the program is invoked will calculate the digest associated with the <pathtoafile> file using the algorithm passed as a parameter (if omitted, SHA1 will be used);
The absolute file of the file with the same calculated hash (if it exists) is printed on the standard output;
If such a file does not exist, an error message is printed on the standard error.
