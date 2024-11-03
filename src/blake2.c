/*
    Blake2b hashing algorithm implementation.
    Made by following sources in README.
    Author: Julien Remmery
    Date: Sunday, November 3, 2024
    Last modified: Sunday, November 3, 2024
*/

#include "blake2.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int pad(uint8_t *data, size_t size, size_t blockSize) {
    memset(data + size, 0, blockSize - size);
    return 0;
}

// Rotate right function for 64-bit integers
uint64_t rotateRight(uint64_t value, int shift) {
    return (value >> shift) | (value << (64 - shift));
}

void mix(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d, uint64_t x, uint64_t y) {
    *a += *b + x;
    *d = rotateRight(*d ^ *a, 32);
    *c += *d;
    *b = rotateRight(*b ^ *c, 24);
    *a += *b + y;
    *d = rotateRight(*d ^ *a, 16);
    *c += *d;
    *b = rotateRight(*b ^ *c, 63);
}

void compress(uint64_t* h, uint8_t* chunk, __uint128_t t, bool isLastBlock) {
    uint64_t v[16], m[16], s[16];
    for (int i = 0; i < 8; i++) {
        v[i] = h[i];
        v[i + 8] = blake2b_IV[i];
    }
    v[12] ^= (uint64_t)(t & 0xFFFFFFFFFFFFFFFF);
    v[13] ^= (uint64_t)(t >> 64);

    if(isLastBlock) {
        v[14] ^= 0xFFFFFFFFFFFFFFFF;
    }

    memcpy(m, chunk, 128);

    for (size_t i = 0; i < 12; i++)
    {
        if (i == 10) {
            // Round 10 uses SIGMA[0]
            for (int j = 0; j < 16; j++) {
                s[j] = blake2b_sigma[0][j];
            }
        } else if (i == 11) {
            // Round 11 uses SIGMA[1]
            for (int j = 0; j < 16; j++) {
                s[j] = blake2b_sigma[1][j];
            }
        } else {
            // For other rounds, use SIGMA[i % 10]
            for (int j = 0; j < 16; j++) {
                s[j] = blake2b_sigma[i % 10][j];
            }
        }
        
        mix(&v[0], &v[4], &v[8],  &v[12], m[s[0]], m[s[1]]);
        mix(&v[1], &v[5], &v[9],  &v[13], m[s[2]], m[s[3]]);
        mix(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]]);
        mix(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]]);

        mix(&v[0], &v[5], &v[10], &v[15], m[s[8]],  m[s[9]]);
        mix(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
        mix(&v[2], &v[7], &v[8],  &v[13], m[s[12]], m[s[13]]);
        mix(&v[3], &v[4], &v[9],  &v[14], m[s[14]], m[s[15]]);
    }

    for (size_t i = 0; i < 8; i++)
    {
        h[i] ^= v[i];
        h[i] ^= v[i + 8];
    }
}

int blake2b(uint8_t *output, const uint8_t *input, size_t inputLen, const uint8_t *key, size_t keyLen, size_t hashLen) {
    uint64_t h[IV_SIZE];
    size_t cBytesCompressed = 0;
    size_t cBytesRemaining = inputLen;

    memcpy(h, blake2b_IV, sizeof(blake2b_IV));

    h[0] ^= (0x01010000 ^ (keyLen << 8) ^ hashLen);

    uint8_t paddedKey[BLAKE2B_BLOCK_SIZE] = {0};
    if (keyLen > 0) {
        memcpy(paddedKey, key, keyLen);
        pad(paddedKey, keyLen, BLAKE2B_BLOCK_SIZE);
        cBytesRemaining += BLAKE2B_BLOCK_SIZE;
    }

    uint8_t *combinedInput = malloc(cBytesRemaining);
    if (keyLen > 0) {
        memcpy(combinedInput, paddedKey, BLAKE2B_BLOCK_SIZE);
        memcpy(combinedInput + BLAKE2B_BLOCK_SIZE, input, inputLen);
    } else {
        memcpy(combinedInput, input, inputLen);
    }

    while (cBytesRemaining > BLAKE2B_BLOCK_SIZE) {
        uint8_t chunk[BLAKE2B_BLOCK_SIZE];
        memcpy(chunk, combinedInput + (cBytesCompressed), BLAKE2B_BLOCK_SIZE);
        cBytesCompressed += BLAKE2B_BLOCK_SIZE;
        cBytesRemaining -= BLAKE2B_BLOCK_SIZE;

        compress(h, chunk, cBytesCompressed, 0);
    }

    if (cBytesRemaining > 0) {
        uint8_t finalChunk[BLAKE2B_BLOCK_SIZE] = {0};
        memcpy(finalChunk, combinedInput + cBytesCompressed, cBytesRemaining);
        cBytesCompressed += cBytesRemaining;

        pad(finalChunk, cBytesRemaining, BLAKE2B_BLOCK_SIZE);
        compress(h, finalChunk, cBytesCompressed, 1);
    }

    memcpy(output, h, hashLen);
    free(combinedInput);

    return 0;
}