#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha256.c"
#include "rc4.c"

static uint8_t target_vector[32] = { 1 };
static uint8_t start_vector[32] = { 1 };
static uint8_t flag_data[75] = { 1 };
static uint32_t hash_data_length = 32;

#define DEBUG 0

int unhex_nibble(char ch){
    if('0' <= ch && ch <= '9') return ch - '0';
    if('a' <= ch && ch <= 'f') return (ch - 'a') + 10;
    if('A' <= ch && ch <= 'A') return (ch - 'A') + 10;
    return -1;
}

int unhex(char *output, char *input, int input_len){
    int nibble1, nibble2; 
    while(input_len > 1){
        nibble1 = unhex_nibble(*input++);
        nibble2 = unhex_nibble(*input++);
        if(nibble1 < 0 || nibble2 < 0) return -1;
        *output++ = (nibble1 << 4) | nibble2;
        input_len -= 2;
    }
    return 0;
}

#if DEBUG
int print_hash(char *hash){
    int i;
    for(i = 0; i < 32; i++) printf("%02hhx", hash[i]);
    printf("\n");
}
#endif

#define GETBIT(vec, bit) (((vec)[(bit) >> 3] >> ((bit) & 7)) & 1)

int main(int argc, char **argv){
    char hex[32*2];
    uint8_t vector[32];
    uint8_t hash[32];
    int bit, i;
    struct timespec t;
    SHA256_CTX sha1, sha2;
    struct rc4_state rc4;
    char c;

    printf("Input key> \n", 0x41414141);

    if(read(STDIN_FILENO, hex, sizeof(hex)) != sizeof(hex)){
        printf("BAD READ\n");
        exit(1);
    }
    
    if(unhex(vector, hex, sizeof(hex))){
        printf("BAD HEX\n");
        exit(2);
    }
    
    sha256_init(&sha2);
    
    for(bit = 0; bit < 256; bit++){
        sha256_init(&sha1);
        sha256_update(&sha1, &((char*)&main)[bit], hash_data_length);
        sha256_final(&sha1, hash);

#if DEBUG
        printf("basis[%d]: ", bit); print_hash(hash);
#endif

        if(GETBIT(vector, bit)){
            sha256_update(&sha2, hash, sizeof(hash));
            for(i = 0; i < 32; i++) start_vector[i] ^= hash[i];
        }
    }

#if DEBUG    
    printf("start_vector:  "); print_hash(start_vector);
    printf("target_vector: "); print_hash(target_vector);
#endif
    
    if(memcmp(start_vector, target_vector, sizeof(target_vector))){
        printf("BAD KEY\n");
        exit(3);
    }

    sha256_final(&sha2, hash);
    rc4_init(&rc4, hash, sizeof(hash));

    for(i = 0; i < sizeof(flag_data); i++){
        rc4_decrypt(&rc4, &flag_data[i], &c, 1);
        putchar(c);
    }
}
