#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// openssl
#include <openssl/sha.h>
#include <stddef.h>

void die(int code, char *msg) {
    if(msg) fprintf(stderr,"ERR: %s\n", msg);
    exit(code);
}

int main(int argc, char **argv) {
    char path[512];
    struct stat fs;
    FILE *fd;
    char *buf;
    size_t len;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char output[65];

    snprintf(path,512,"%s",argv[1]);
    if( stat(path,&fs) <0) die(1, "stat");
    fprintf(stderr,"%s %ld\n",path, fs.st_size);

    if(!fs.st_size) die(1, "stat size");

    fd = fopen(path,"r");
    if(!fd) die(1, "fopen");

    buf = malloc(fs.st_size);
    if(!buf) die(1, "malloc");

    len = fread(buf,1,fs.st_size,fd);
    if(len != fs.st_size) die(1, "fread");

    SHA256_Update(&sha256, buf, len);
    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", (unsigned char)hash[i]);
    output[64] = 0;

    fprintf(stderr,"%s\n",output);

    free(buf);
    exit(0);
}
