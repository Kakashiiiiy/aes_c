#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

typedef struct chiphertex
{
        uint8_t **array;
        int index;
}chiphertex_t;

void cbcdec(chiphertex_t *input_t,chiphertex_t* output_t, aes_key_t *key,uint8_t * inital_vek) {
        //IV XOR
        uint8_t *retarr =malloc(16);       
        aes_block_decrypt(input_t->array[0], *key, retarr);
        for (int i = 0; i < 16; ++i)
        {
                retarr[i]=retarr[i]^inital_vek[i];
        }
        output_t->array[0]=retarr;

        //CBC DECRYPT
        for (int i = 1; i < input_t->index; ++i)
        {
                uint8_t *retarr =malloc(16);
                aes_block_decrypt(input_t->array[i], *key, retarr);
                for (int z = 0; z < 16; ++z)
                {
                        retarr[z]=retarr[z]^input_t->array[i-1][z];
                }
                output_t->array[i]=retarr;
        }
        output_t->index = input_t->index;
}

void cbcenc(chiphertex_t *input_t,chiphertex_t* output_t, aes_key_t *key,uint8_t * inital_vek){
        uint8_t *retarr =malloc(16);
        for (int i = 0; i < 16; ++i)
        {
                input_t->array[0][i]=input_t->array[0][i]^inital_vek[i];
        }
        aes_block_encrypt(input_t->array[0], *key, retarr);
        output_t->array[0]=retarr;

        //CBC encrypt
        for (int i = 1; i < input_t->index; ++i)
        {
                uint8_t *retarr =malloc(16);       
                aes_block_encrypt(input_t->array[i], *key, retarr);
                for (int z = 0; z < 16; ++z)
                {
                        retarr[z]=retarr[z]^input_t->array[i-1][z];
                }
                output_t->array[i]=retarr;
        }
        output_t->index = input_t->index;
}

void dececb(chiphertex_t *input_t,chiphertex_t* output_t, aes_key_t *key){
        for (int i = 0; i < input_t->index; ++i)
        {      
                uint8_t *retarr =malloc(16);
                aes_block_decrypt(input_t->array[i], *key, retarr);
                output_t->array[i]=retarr;
        }       
        output_t->index = input_t->index;
}


void encecb(chiphertex_t *input_t,chiphertex_t* output_t, aes_key_t *key){
        for (int i = 0; i < input_t->index; ++i)
        {       
                uint8_t *retarr =malloc(16); 
                aes_block_encrypt(input_t->array[i], *key, retarr);
                output_t->array[i]=retarr;
        }
        output_t->index = input_t->index;
}

void ofb(chiphertex_t *input_t,chiphertex_t* output_t, aes_key_t *key, uint8_t* iv) {
        for (int i = 0; i < input_t->index; ++i)
        {      
                uint8_t *retarr =malloc(16);
                aes_block_encrypt(iv, *key, iv);
                for (int x = 0; x < 16; ++x)
                {
                        retarr[x]=input_t->array[i][x]^iv[x];
                }
                output_t->array[i]=retarr;
        }
        output_t->index = input_t->index;
}

void getiv(uint8_t* iv, char const * argv[],struct stat *size_iv, FILE*fp_iv){
    fp_iv = fopen(argv[5], "r");
    int fd_iv = fileno(fp_iv);
    fstat(fd_iv, size_iv);
    if (size_iv->st_size!=16)
    {
        printf("[-]IV has wrong length: %ld\n",size_iv->st_size);
        exit(1);
    }else 
    {
        printf("[+]IV has Bit length: %ld\n", size_iv->st_size);
        for (int i = 0; i < 16; ++i)
        {
            iv[i]=fgetc(fp_iv);
        }
    }    
}

int main(int argc, char const *argv[])
{
        FILE *fp_i,*fp_w, *fp_iv, *fp_key;
        struct stat size_i;
        struct stat size_iv;
        struct stat size_key;

        fp_i = fopen(argv[2], "r");
        fp_w = fopen(argv[3], "a+");
        fp_key = fopen(argv[4], "r");
        fp_iv = NULL;
        if (fp_i == NULL)
        {
                fprintf(stderr,"Error open file argv[1]");
                return 1;
        }else fprintf(stderr,"%s\n", "[+]Sucessfully opened file 1");
        printf("[+]Input File: %s\n", argv[2]);
        int fd_i = fileno(fp_i);
        int fd_key = fileno(fp_key);

        fstat(fd_i, &size_i);
        fstat(fd_key, &size_key);

        uint8_t iv[16];
        aes_key_t key;
        chiphertex_t ober={malloc(size_i.st_size),0};
        uint8_t *key_a = (uint8_t*)calloc(size_key.st_size, 1);
        if (size_key.st_size!=16&&size_key.st_size!=32&&size_key.st_size!=24)
        {
            printf("[-]Key has not 128, 192 or 256 Bit length: %ld\n", size_key.st_size*8);
            return 1;
        }else 
        {
            printf("[+]Key has %ld Bit size\n", size_key.st_size*8);
            for (int i = 0; i < 16; ++i)
            {
                 key_a[i]=fgetc(fp_key);
            } 
        }
        int kill=0;
        while(kill==0){
                uint8_t *a = malloc(16);
                for (int x = 0; x < 16; ++x)
                {
                    int y = fgetc(fp_i);
                    if (y==EOF){kill=x;goto EXIT;}
                    a[x]=y;     
                }
                ober.array[ober.index++]=a;
                continue;
                EXIT:;
                if (kill == 0)
                {
                    kill = 16;
                }else{
                    for (; kill < 16; kill++)
                    {
                            a[kill]=0;
                    }
                    ober.array[ober.index++]=a;
                }
        }
        //KEYSETUP
        aes_set_key(&key, key_a, size_key.st_size);
        
        chiphertex_t ergebnis={malloc(size_i.st_size),0};
        if (!strcmp(argv[1],"dCBC"))
        {
                getiv(iv, argv, &size_iv, fp_iv);
                cbcdec(&ober, &ergebnis, &key, iv);
                printf("%s\n", "[+]Decryption MODE CBC");
        }else if (!strcmp(argv[1],"eCBC"))
        {
                getiv(iv, argv, &size_iv, fp_iv);
                cbcenc(&ober, &ergebnis, &key, iv);
                printf("%s\n", "[+]Encryption MODE CBC");

        }else if(!strcmp(argv[1], "dECB"))
        {
                dececb(&ober, &ergebnis, &key);
                printf("%s\n", "[+]Decryption MODE ECB");
        }else if(!strcmp(argv[1], "eECB"))
        {
                encecb(&ober, &ergebnis, &key);
                printf("%s\n", "[+]Encryption MODE ECB");
        }else if ((!strcmp(argv[1], "eOFB"))||(!strcmp(argv[1], "dOFB"))||(!strcmp(argv[1], "OFB")))
        {
                getiv(iv, argv, &size_iv, fp_iv);
                ofb(&ober, &ergebnis, &key, iv);
                printf("%s\n", "[+]MODE OFB");
        }

        for(double i = 0; i < ergebnis.index; ++i)
        {
                for (int x = 0; x < 16; ++x)
                {
                        fputc(ergebnis.array[(int)i][x], fp_w);
                }
                //printf("\rWrote Percentage: %lf", i/ergebnis.index*100);
                //fflush(stdout);
        }
        printf("\n");
        return 0;
}
