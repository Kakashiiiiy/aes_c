#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
/** 
                DO NOT CHANGE ANYTHING HERE!
*/
//CODE PROVIDED BY https://www.emsec.ruhr-uni-bochum.de/chair/home/

typedef struct chiphertex
{
        uint8_t **array;
        int index;
}chiphertex_t;

extern int aesha();
int test()
{
        int failed = 0;
        if (test_key_addition() == 0)
                printf("[+] passed aes_key_addition()\n");
        else {
                printf("[-] failed aes_key_addition()\n");
                failed++;
        }

        if (test_subbytes() == 0)
                printf("[+] passed aes_subbytes()\n");
        else {
                printf("[-] failed aes_subbytes()\n");
                failed++;
        }
        if (test_inv_subbytes() == 0)
                printf("[+] passed aes_inv_subbytes()\n");
        else {
                printf("[-] failed aes_inv_subbytes()\n");
                failed++;
        }

        if (test_shiftrows() == 0)
                printf("[+] passed aes_shiftrows()\n");
        else {
                printf("[-] failed aes_shiftrows()\n");
                failed++;
        }
        if (test_inv_shiftrows() == 0)
                printf("[+] passed aes_inv_shiftrows()\n");
        else {
                printf("[-] failed aes_inv_shiftrows()\n");
                failed++;
        }
        
        if (test_mixcolumns() == 0)
                printf("[+] passed aes_mixcolumns()\n");
        else {
                printf("[-] failed aes_mixcolumns()\n");
                failed++;
        }
        if (test_inv_mixcolumns() == 0)
                printf("[+] passed aes_inv_mixcolumns()\n");
        else {
                printf("[-] failed aes_inv_mixcolumns()\n");
                failed++;
        }

        if (failed != 0) {
                printf("[-] fix the '%d' error(s) in the round transformations first!\n", failed);
                return -1;
        } 

        failed = 0;
        if (test_key_schedule_128() == 0) 
                printf("[+] passed aes_key_schedule for 128-bit key size()\n");
        else {
                printf("[-] failed aes_key_schedule for 128-bit key size()\n");
                failed++;
        }
        if (test_key_schedule_192() == 0) 
                printf("[+] passed aes_key_schedule for 192-bit key size()\n");
        else {
                printf("[-] failed aes_key_schedule for 192-bit key size()\n");
                failed++;
        }
        if (test_key_schedule_256() == 0) 
                printf("[+] passed aes_key_schedule for 256-bit key size()\n");
        else {
                printf("[-] failed aes_key_schedule for 256-bit key size()\n");
                failed++;
        }
        if (failed != 0) {
                printf("[-] fix the '%d' error(s) in the key schedule methods first!\n", failed);
                return -1;
        } 

        failed = 0;
        if (test_block_encrypt_128() == 0) 
                printf("[+] passed aes_block_encrypt for 128-bit key size()\n");
        else {
                printf("[-] failed aes_block_encrypt for 128-bit key size()\n");
                failed++;
        }
        if (test_block_encrypt_192() == 0) 
                printf("[+] passed aes_block_encrypt for 192-bit key size()\n");
        else {
                printf("[-] failed aes_block_encrypt for 192-bit key size()\n");
                failed++;
        }
        if (test_block_encrypt_256() == 0) 
                printf("[+] passed aes_block_encrypt for 256-bit key size()\n");
        else {
                printf("[-] failed aes_block_encrypt for 256-bit key size()\n");
                failed++;
        }
        if (failed != 0) {
                printf("[-] fix the '%d' error(s) in the aes_block_encrypt methods first!\n", failed);
                return -1;
        } 

        failed = 0;
        if (test_block_decrypt_128() == 0) 
                printf("[+] passed aes_block_decrypt for 128-bit key size()\n");
        else {
                printf("[-] failed aes_block_decrypt for 128-bit key size()\n");
                failed++;
        }
        if (test_block_decrypt_192() == 0) 
                printf("[+] passed aes_block_decrypt for 192-bit key size()\n");
        else {
                printf("[-] failed aes_block_decrypt for 192-bit key size()\n");
                failed++;
        }
        if (test_block_decrypt_256() == 0) 
                printf("[+] passed aes_block_decrypt for 256-bit key size()\n");
        else {
                printf("[-] failed aes_block_decrypt for 256-bit key size()\n");
                failed++;
        }
        if (failed != 0) {
                printf("[-] fix the '%d' error(s) in the aes_block_decrypt methods first!\n", failed);
                return -1;
        } 
        printf("[+] passed all tests! :)\n");
        aesha();
        return 0;
}
