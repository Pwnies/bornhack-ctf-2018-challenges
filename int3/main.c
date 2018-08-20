#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "flag_data.h"

int check_flag(char *flag){
    char out[FLAG_LENGTH];
    int i, j;
    int n = strlen(flag);
    char c = 0;

    if(n != FLAG_LENGTH) return 0;

    for(i = 0; i < n; i++)
        for(j = 0; j < n-i; j++)
            flag_data[j] ^= flag[j + i];

    for(i = 0; i < n; i++) c |= flag_data[i];

    return c ? 0 : 1;
}

int main(int argc, char **argv){
    char *arg = argv[1];
    int res = 0;

    if(argc != 2){
        printf("%s <flag>\n", argv[0]);
        return 1;
    }

    if(check_flag(argv[1])){
        printf("GOOD FLAG!\n");
        return 0;
    }

    printf("BAD FLAG!\n");
    return 1;
}
