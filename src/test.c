#include "blake2.h"
#include <string.h>
#include <stdio.h>

int main() {
    const char *message = "Hello, World!";
    const char key[] = "secret_key";
    uint8_t hash[BLAKE2B_DIGEST_LENGTH];

    blake2b(hash, message, strlen(message), key, strlen(key), BLAKE2B_DIGEST_LENGTH);

    for (int i = 0; i < BLAKE2B_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}