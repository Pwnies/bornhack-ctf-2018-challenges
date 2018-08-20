#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

//flag{717b5d94-1cd24a57-9c8ce368}

char table[16] = "52afc31b9e784d60";
char entries[8] = { 6, 4, 13, 1, 12, 2, 0, 10 };

void denied() {
  puts("The key is wrong :(");
  exit(-1);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        puts("Please give me a key!");
        exit(0);
    }

    char* rest = argv[1];
    // check format
    if (strlen(rest) != 26 || rest[8] != '-' || rest[17] != '-') {
        denied();
    }

    // check first part
    if (strncmp(rest, "717b5d94", 8)) {
        denied();
    }

    // check second part
    rest += 9;
    for (int i = 0; i < 8; i++) {
        if (table[entries[i]] != rest[i]) {
            denied();
        }
    }

    // check third part
    rest += 9;
    for (int i = 0; i < 8; i++) {
        if (table[(argv[1][i] + argv[1][i+9]) % 16] != rest[i]) {
            denied();
        }
    }

    // You win!
    printf("Congratulations! The flag is flag{%s}\n", argv[1]);

    return 0;
}
