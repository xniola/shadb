#Compila il programma
all:
	gcc -o shadb shadb.c readwrite.c sha1.c sha2.c fileInfo.c
