#include <stddef.h>
#include <stdio.h>
struct rc4_state {
        unsigned char i, j;
            unsigned char s[256];
};
void inline static swap_bytes(unsigned char *a, unsigned char *b){
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

void rc4_init(struct rc4_state *state, unsigned char *key, size_t key_len){
    unsigned char j;
    int i;
    for(i = 0; i < 256; i++)
        state->s[i] = (unsigned char) i;
    for(j = i = 0; i < 256; i++){
        j += state->s[i] + key[i % key_len];
        swap_bytes(&state->s[i], &state->s[j]);
    }
    state->i = state->j = 0;
}

#define rc4_decrypt rc4_encrypt
void rc4_encrypt(struct rc4_state *state, char *inbuf, char *outbuf, size_t buflen){
    int x;
    unsigned char y;
    for(x = 0; x < buflen; x++){
        state->i += 1;
        state->j += state->s[state->i];
        swap_bytes(&state->s[state->i], &state->s[state->j]);
        y = state->s[state->i] + state->s[state->j];
        outbuf[x] = inbuf[x] ^ state->s[y];
    }
}
