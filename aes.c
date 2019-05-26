#include "aes.h"
#include <stdio.h>
#include <string.h>

//TEMPLATE PROVIDED BY https://www.emsec.ruhr-uni-bochum.de/chair/home/
static inline u8 gf_multiply(u8 x, u8 y){
        u8 p = 0;
        while(y > 0){
            if (y & 1) p^=x;
            if (x&0x80) x = (x<<1) ^ 0x11b; //0x11b ist das Reduktionspolynom;
            else x <<=1;
            y>>=1;
        }
        return p;
}
static void aes_key_addition(aes_state_t* state, aes_key_t k, u8 r)
{
    for (int i = 0; i < 16; ++i)state->s[i] = state->s[i]^k.round_key[i+r*16];
} 

static void aes_subbytes(aes_state_t* state)
{
    for (int i = 0; i < 16; ++i)state->s[i] = sbox[state->s[i]];
}

static void aes_shiftrows(aes_state_t* state)
{
    u8 hilf[16];
    for (int i = 0; i < 16; ++i)
    {
            hilf[i]=state->s[i];
    }
    for (int i = 0; i < 4; i++)
    {
            state->s[i*4]=hilf[i*4];
            state->s[i*4+1]=hilf[(i*4+5)&0x0F];
            state->s[i*4+2]=hilf[(i*4+10)&0x0F];
            state->s[i*4+3]=hilf[(i*4+15)&0x0F];
    }
    return;
}

static void aes_mixcolumns(aes_state_t* state)
{
    u8 hilf[16];
    for (int i = 0; i < 16; ++i)
    {
            hilf[i]=state->s[i];
    }
    for (int i = 0; i < 4; ++i)
    {
            state->s[i*4+0]=gf_multiply(hilf[i*4+0],0x02)^gf_multiply(hilf[i*4+1],0x03)^gf_multiply(hilf[i*4+2],0x01)^gf_multiply(hilf[i*4+3],0x01);
            state->s[i*4+1]=gf_multiply(hilf[i*4+0],0x01)^gf_multiply(hilf[i*4+1],0x02)^gf_multiply(hilf[i*4+2],0x03)^gf_multiply(hilf[i*4+3],0x01);
            state->s[i*4+2]=gf_multiply(hilf[i*4+0],0x01)^gf_multiply(hilf[i*4+1],0x01)^gf_multiply(hilf[i*4+2],0x02)^gf_multiply(hilf[i*4+3],0x03);
            state->s[i*4+3]=gf_multiply(hilf[i*4+0],0x03)^gf_multiply(hilf[i*4+1],0x01)^gf_multiply(hilf[i*4+2],0x01)^gf_multiply(hilf[i*4+3],0x02);
    }
    return;
}

static void aes_inv_subbytes(aes_state_t* state)
{
    for (int i = 0; i < 16; ++i)state->s[i] = rsbox[((state->s[i]>>4)*16)+(state->s[i]&0x0F)];
}

static void aes_inv_shiftrows(aes_state_t* state) 
{
    u8 hilf[16];
    for (int i = 0; i < 16; ++i)
    {
            hilf[i]=state->s[i];
    }
    for (int i = 0; i < 4; i++)
    {
            state->s[i*4]=hilf[i*4];
            state->s[(i*4+5)&0x0F]=hilf[i*4+1];
            state->s[(i*4+10)&0x0F]=hilf[i*4+2];
            state->s[(i*4+15)&0x0F]=hilf[i*4+3];
    }
    return;
}

static void aes_inv_mixcolumns(aes_state_t* state)
{
    u8 hilf[16];
    for (int i = 0; i < 16; ++i)
    {
            hilf[i]=state->s[i];
    }
    for (int i = 0; i < 4; ++i)
    {
            state->s[i*4+0]=gf_multiply(hilf[i*4+0],0x0E)^gf_multiply(hilf[i*4+1],0x0B)^gf_multiply(hilf[i*4+2],0x0D)^gf_multiply(hilf[i*4+3],0x09);
            state->s[i*4+1]=gf_multiply(hilf[i*4+0],0x09)^gf_multiply(hilf[i*4+1],0x0E)^gf_multiply(hilf[i*4+2],0x0B)^gf_multiply(hilf[i*4+3],0x0D);
            state->s[i*4+2]=gf_multiply(hilf[i*4+0],0x0D)^gf_multiply(hilf[i*4+1],0x09)^gf_multiply(hilf[i*4+2],0x0E)^gf_multiply(hilf[i*4+3],0x0B);
            state->s[i*4+3]=gf_multiply(hilf[i*4+0],0x0B)^gf_multiply(hilf[i*4+1],0x0D)^gf_multiply(hilf[i*4+2],0x09)^gf_multiply(hilf[i*4+3],0x0E);
    }
    return;
}

static void funktion_g(u8 *output,u8 *keys,u8 rc_value){
    for (int i = 0; i < 4; ++i)
    {
        output[i]= sbox[(keys[(i+1)%4]>>4)*16+(keys[(i+1)%4]&0x0F)];
    }
    output[0]=output[0]^Rcon[rc_value];
    return;
}

static void aes_set_key_sub_128(aes_key_t *k,u8 *key) {
    for (int i = 0; i < 4; ++i)
    {
        k->round_key[i*4+0]=key[i*4+0];
        k->round_key[i*4+1]=key[i*4+1];
        k->round_key[i*4+2]=key[i*4+2];
        k->round_key[i*4+3]=key[i*4+3];
    }
    for (int i = 4; i < AES_128_LAST_WORD; ++i)
    {
        if(i%4==0){
            u8 hilf[4];
            funktion_g(hilf, &(k->round_key[(i-1)*4]), i/4);
            k->round_key[i*4+0]=hilf[0]^k->round_key[(i-4)*4+0];
            k->round_key[i*4+1]=hilf[1]^k->round_key[(i-4)*4+1];
            k->round_key[i*4+2]=hilf[2]^k->round_key[(i-4)*4+2];
            k->round_key[i*4+3]=hilf[3]^k->round_key[(i-4)*4+3];
            continue;
        }
        k->round_key[i*4+0]=k->round_key[(i-1)*4+0]^k->round_key[(i-4)*4+0];
        k->round_key[i*4+1]=k->round_key[(i-1)*4+1]^k->round_key[(i-4)*4+1];
        k->round_key[i*4+2]=k->round_key[(i-1)*4+2]^k->round_key[(i-4)*4+2];
        k->round_key[i*4+3]=k->round_key[(i-1)*4+3]^k->round_key[(i-4)*4+3];
    }
}

static void aes_set_key_sub_192(aes_key_t *k,u8 *key) {
    for (int i = 0; i < 6; ++i)
    {
        k->round_key[i*4+0]=key[i*4+0];
        k->round_key[i*4+1]=key[i*4+1];
        k->round_key[i*4+2]=key[i*4+2];
        k->round_key[i*4+3]=key[i*4+3];
    }
    for (int i = 6; i < AES_192_LAST_WORD; ++i)
    {
        if(i%6==0){
            u8 hilf[4];
            funktion_g(hilf, &(k->round_key[(i-1)*4]), i/6);
            k->round_key[i*4+0]=hilf[0]^k->round_key[(i-6)*4+0];
            k->round_key[i*4+1]=hilf[1]^k->round_key[(i-6)*4+1];
            k->round_key[i*4+2]=hilf[2]^k->round_key[(i-6)*4+2];
            k->round_key[i*4+3]=hilf[3]^k->round_key[(i-6)*4+3];
            continue;
        }
        k->round_key[i*4+0]=k->round_key[(i-1)*4+0]^k->round_key[(i-6)*4+0];
        k->round_key[i*4+1]=k->round_key[(i-1)*4+1]^k->round_key[(i-6)*4+1];
        k->round_key[i*4+2]=k->round_key[(i-1)*4+2]^k->round_key[(i-6)*4+2];
        k->round_key[i*4+3]=k->round_key[(i-1)*4+3]^k->round_key[(i-6)*4+3];
    }
    
}

static void aes_set_key_sub_256(aes_key_t *k,u8 *key) {
    for (int i = 0; i < 8; ++i)
    {
        k->round_key[i*4+0]=key[i*4+0];
        k->round_key[i*4+1]=key[i*4+1];
        k->round_key[i*4+2]=key[i*4+2];
        k->round_key[i*4+3]=key[i*4+3];
    }
    for (int i = 8; i < AES_256_LAST_WORD; ++i)
    {
        if(i%8==0){
            u8 hilf[4];
            funktion_g(hilf, &(k->round_key[(i-1)*4]), i/8);
            k->round_key[i*4+0]=hilf[0]^k->round_key[(i-8)*4+0];
            k->round_key[i*4+1]=hilf[1]^k->round_key[(i-8)*4+1];
            k->round_key[i*4+2]=hilf[2]^k->round_key[(i-8)*4+2];
            k->round_key[i*4+3]=hilf[3]^k->round_key[(i-8)*4+3];
            continue;
        }
        if(((i+4)%8)==0){
            u8 v0 = k->round_key[(i-1)*4+0];
            u8 v1 = k->round_key[(i-1)*4+1];
            u8 v2 = k->round_key[(i-1)*4+2];
            u8 v3 = k->round_key[(i-1)*4+3];
            k->round_key[i*4+0]=sbox[(v0>>4)*16+(v0&0x0F)]^k->round_key[(i-8)*4+0];
            k->round_key[i*4+1]=sbox[(v1>>4)*16+(v1&0x0F)]^k->round_key[(i-8)*4+1];
            k->round_key[i*4+2]=sbox[(v2>>4)*16+(v2&0x0F)]^k->round_key[(i-8)*4+2];
            k->round_key[i*4+3]=sbox[(v3>>4)*16+(v3&0x0F)]^k->round_key[(i-8)*4+3];    
            continue;        
        }
        k->round_key[i*4+0]=k->round_key[(i-1)*4+0]^k->round_key[(i-8)*4+0];
        k->round_key[i*4+1]=k->round_key[(i-1)*4+1]^k->round_key[(i-8)*4+1];
        k->round_key[i*4+2]=k->round_key[(i-1)*4+2]^k->round_key[(i-8)*4+2];
        k->round_key[i*4+3]=k->round_key[(i-1)*4+3]^k->round_key[(i-8)*4+3];
    }
}

void aes_set_key(aes_key_t* k, u8* key, int key_len)
{
        if (k == NULL)
                        return;
        switch (key_len) {
        case (AES_128_KEY_BIT_LEN / 8): k->key_bit_size = AES_128_KEY_BIT_LEN;
                        break;
        case (AES_192_KEY_BIT_LEN / 8): k->key_bit_size = AES_192_KEY_BIT_LEN;
                        break;
        case (AES_256_KEY_BIT_LEN / 8): k->key_bit_size = AES_256_KEY_BIT_LEN;
                        break;
        default:                        k->key_bit_size = 0;
                        printf("[error] : aes_set_key() : key length %d is invalid!\n", key_len);
                        break;
        }
        memset(k->round_key, 0, AES_256_NB);
        switch(k->key_bit_size){
        case (AES_128_KEY_BIT_LEN) : aes_set_key_sub_128(k,key); break;
        case (AES_192_KEY_BIT_LEN) : aes_set_key_sub_192(k,key); break;
        case (AES_256_KEY_BIT_LEN) : aes_set_key_sub_256(k,key); break;
        }
}

static void aes_block_encrypt_sub(aes_state_t *state, aes_key_t *key, u8 num_of_rounds) {
    aes_key_addition(state, *key, 0);
    for (int i = 1; i < num_of_rounds; ++i)
    {
        aes_subbytes(state);
        aes_shiftrows(state);
        aes_mixcolumns(state);
        aes_key_addition(state, *key, i);
    }
    aes_subbytes(state);
    aes_shiftrows(state);
    aes_key_addition(state, *key, num_of_rounds);
}


void aes_block_encrypt(u8 ptx[AES_BYTE_BLOCK_SIZE], aes_key_t key,u8 ctx[AES_BYTE_BLOCK_SIZE])
{
        aes_state_t state; 
        memcpy(state.s, ptx, AES_BYTE_BLOCK_SIZE);

        u8 num_of_rounds = 0;
        switch(key.key_bit_size) {
        case AES_128_KEY_BIT_LEN: num_of_rounds = AES_128_NUM_OF_ROUNDS; break;
        case AES_192_KEY_BIT_LEN: num_of_rounds = AES_192_NUM_OF_ROUNDS; break;
        case AES_256_KEY_BIT_LEN: num_of_rounds = AES_256_NUM_OF_ROUNDS; break;       
        }
        switch(num_of_rounds){
                case(AES_128_NUM_OF_ROUNDS): aes_block_encrypt_sub(&state,&key,AES_128_NUM_OF_ROUNDS);break;
                case(AES_192_NUM_OF_ROUNDS): aes_block_encrypt_sub(&state,&key,AES_192_NUM_OF_ROUNDS);break;
                case(AES_256_NUM_OF_ROUNDS): aes_block_encrypt_sub(&state,&key,AES_256_NUM_OF_ROUNDS);break;
        }
        memcpy(ctx, state.s, AES_BYTE_BLOCK_SIZE);        

}

static void aes_block_decrypt_sub(aes_state_t *state, aes_key_t *key, u8 num_of_rounds) {
    aes_key_addition(state, *key, num_of_rounds);
    aes_inv_shiftrows(state);
    aes_inv_subbytes(state);
    for (int i = num_of_rounds-1; i >= 1; --i)
    {
        aes_key_addition(state, *key, i);
        aes_inv_mixcolumns(state);
        aes_inv_shiftrows(state);
        aes_inv_subbytes(state);
    }
    aes_key_addition(state, *key, 0);
}

void aes_block_decrypt(u8 ctx[AES_BYTE_BLOCK_SIZE], aes_key_t key,u8 ptx[AES_BYTE_BLOCK_SIZE])
{
        aes_state_t state; 
        memcpy(state.s, ctx, AES_BYTE_BLOCK_SIZE);

        u8 num_of_rounds = 0;
        switch(key.key_bit_size) {
        case AES_128_KEY_BIT_LEN: num_of_rounds = AES_128_NUM_OF_ROUNDS;
                        break;
        case AES_192_KEY_BIT_LEN: num_of_rounds = AES_192_NUM_OF_ROUNDS;
                        break;
        case AES_256_KEY_BIT_LEN: num_of_rounds = AES_256_NUM_OF_ROUNDS;
                        break;
        }
        switch(num_of_rounds){
                case(AES_128_NUM_OF_ROUNDS): aes_block_decrypt_sub(&state, &key, AES_128_NUM_OF_ROUNDS);break;
                case(AES_192_NUM_OF_ROUNDS): aes_block_decrypt_sub(&state, &key, AES_192_NUM_OF_ROUNDS);break;
                case(AES_256_NUM_OF_ROUNDS): aes_block_decrypt_sub(&state, &key, AES_256_NUM_OF_ROUNDS);break;
        }

        memcpy(ptx, state.s, AES_BYTE_BLOCK_SIZE);
}
/*
int test_key_addition()
{
        u8 input_ptx[AES_BYTE_BLOCK_SIZE] = {
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        };
        u8 input_key[AES_BYTE_BLOCK_SIZE] = {
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
                0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08
        };

        aes_state_t state; 
        memcpy(state.s, input_ptx, 16);
        aes_key_t key;
        memcpy(key.round_key, input_key, 16);

        aes_key_addition(&state, key, 0);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_subbytes()
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
                0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x4c, 0x08
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 
                0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x29, 0x30
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_subbytes(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_inv_subbytes() 
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 
                0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x29, 0x30

        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
                0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x4c, 0x08
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_inv_subbytes(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_shiftrows()
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 
                0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 
                0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_shiftrows(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_inv_shiftrows()
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 
                0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 
                0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_inv_shiftrows(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_mixcolumns()
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 
                0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 
                0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c, 
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_mixcolumns(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_inv_mixcolumns()
{
        u8 input[AES_BYTE_BLOCK_SIZE] = {
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 
                0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c, 
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 
                0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5
        };

        aes_state_t state;
        memcpy(state.s, input, 16);

        aes_inv_mixcolumns(&state);

        if (memcmp(output, state.s, 16) == 0)
                return 0;
        return -1;
}

int test_key_schedule_128()
{
        u8 input[AES_128_KEY_BYTE_LEN] = {
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
        };        
        u8 output[AES_128_KEY_BYTE_LEN] = {
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,
                0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6,
        };

        aes_key_t key;
        aes_set_key(&key, input, AES_128_KEY_BYTE_LEN);

        if (memcmp(output, key.round_key + 16*10, 16) == 0)
                return 0;
        return -1;
}

int test_key_schedule_192()
{
        u8 input[AES_192_KEY_BYTE_LEN] = {
                0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b 
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xe9, 0x8b, 0xa0, 0x6f, 0x44, 0x8c, 0x77, 0x3c,
                0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00, 0x22, 0x02
        };

        aes_key_t key;
        aes_set_key(&key, input, AES_192_KEY_BYTE_LEN);

        if (memcmp(output, key.round_key + 16*12, 16) == 0)
                return 0;
        return -1;
}

int test_key_schedule_256()
{
        u8 input[AES_256_KEY_BYTE_LEN] = {
                0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
                0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
                0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
                0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };        
        u8 output[AES_BYTE_BLOCK_SIZE] = {
                0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b,
                0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c, 0x63, 0x1e
        };

        aes_key_t key;
        aes_set_key(&key, input, AES_256_KEY_BYTE_LEN);

        if (memcmp(output, key.round_key + 16*14, 16) == 0)
                return 0;
        return -1;
}

int test_block_encrypt_128()
{
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 key[AES_128_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        u8 ctx_ref[AES_BYTE_BLOCK_SIZE] = {
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        };
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_128_KEY_BYTE_LEN);

        aes_block_encrypt(ptx, k, ctx);

        if (memcmp(ctx_ref, ctx, 16) == 0)
                return 0;
        return -1;
}

int test_block_encrypt_192()
{
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 key[AES_192_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        };
        u8 ctx_ref[AES_BYTE_BLOCK_SIZE] = {
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 
                0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
        };
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_192_KEY_BYTE_LEN);

        aes_block_encrypt(ptx, k, ctx);

        if (memcmp(ctx_ref, ctx, 16) == 0)
                return 0;
        return -1;
}

int test_block_encrypt_256()
{
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 key[AES_256_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        u8 ctx_ref[AES_BYTE_BLOCK_SIZE] = {
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, 
        };
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_256_KEY_BYTE_LEN);

        aes_block_encrypt(ptx, k, ctx);

        if (memcmp(ctx_ref, ctx, 16) == 0)
                return 0;
        return -1;
}

int test_block_decrypt_128()
{
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        };
        u8 key[AES_128_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        u8 ptx_ref[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_128_KEY_BYTE_LEN);

        aes_block_decrypt(ctx, k, ptx);

        if (memcmp(ptx_ref, ptx, 16) == 0)
                return 0;
        return -1;
}

int test_block_decrypt_192()
{
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 
                0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91

        };
        u8 key[AES_192_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        };
        u8 ptx_ref[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_192_KEY_BYTE_LEN);

        aes_block_decrypt(ctx, k, ptx);

        if (memcmp(ptx_ref, ptx, 16) == 0)
                return 0;
        return -1;
}

int test_block_decrypt_256()
{
        u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, 
        };
        u8 key[AES_256_KEY_BYTE_LEN] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        u8 ptx_ref[AES_BYTE_BLOCK_SIZE] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        u8 ptx[AES_BYTE_BLOCK_SIZE] = {
                0
        };

        aes_key_t k;
        aes_set_key(&k, key, AES_256_KEY_BYTE_LEN);

        aes_block_decrypt(ctx, k, ptx);

        if (memcmp(ptx_ref, ptx, 16) == 0)
                return 0;
        return -1;
}*/
/*
int aesha() { //Hausaufgabe 9
    u8 key[AES_128_KEY_BYTE_LEN] = {0x60, 0x43, 0x06, 0xE0, 0xF9 , 0x02, 0x0C, 0xEB ,
                                    0x0C, 0x68, 0xDC, 0x73, 0xF0, 0x63, 0x7F ,0x4B};
    u8 ctx[AES_BYTE_BLOCK_SIZE] = {
                0xC7, 0xda, 0xb3, 0x8d, 0xef, 0x97, 0xea, 0xb1,
                0x02, 0x43, 0xd4, 0x08, 0xb6, 0x61, 0xa0, 0xe1};

    u8 key1[AES_128_KEY_BYTE_LEN] = {0xf2, 0xa0, 0x25, 0x96, 0x96, 0xef, 0x69, 0x3c,
                                     0xa7, 0x10, 0x2b, 0x8d, 0xb5, 0x25, 0x3a, 0x3f};

    u8 ctx1[AES_BYTE_BLOCK_SIZE] = {0x54, 0x01, 0x5c, 0xfc, 0x87, 0x52, 0xc1, 0xe6,
                                    0x61, 0xef, 0x26, 0xf9, 0xe2, 0xa6, 0xe5, 0xd4};  


    aes_state_t state; 
    memcpy(state.s, ctx1, AES_BYTE_BLOCK_SIZE);
    aes_key_t k;
    aes_set_key(&k, key1, AES_128_KEY_BYTE_LEN);

    for (int i = 0; i < 16; ++i)
    {
        printf("%X:", k.round_key[i+16]);
        state.s[i]=state.s[i]^k.round_key[i+16];

    }
    printf("\n");
    printf("NachK1\n");
    for (int i = 0; i < 16; ++i)
    {
        printf("%X:", state.s[i]);
    }
    aes_inv_mixcolumns(&state);
    printf("\n");
    printf("MIXCOLUMNS\n");
    for (int i = 0; i < 16; ++i)
    {
        printf("%X:", state.s[i]);
    }
    aes_inv_shiftrows(&state);
    printf("\n");
    printf("ShiftRows\n");
    for (int i = 0; i < 16; ++i)
    {
        printf("%X:", state.s[i]);
    }
    aes_inv_subbytes(&state);
    printf("\n");
    printf("INVSUB\n");
    for (int i = 0; i < 16; ++i)
    {
        printf("%X:", state.s[i]);
    }
    printf("\n");
    printf("KeyADD\n");
    for (int i = 0; i < 16; ++i)
    {
        state.s[i]=state.s[i]^k.round_key[i];
        printf("%X:", state.s[i]);
    }
    return 1;
}*/
