/*
    Blake2b hashing algorithm implementation.
    Made by following sources in README.
    Author: Julien Remmery
    Date: Sunday, November 3, 2024
    Last modified: Sunday, November 3, 2024
*/

#ifndef BLK_H
#define BLK_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    BLK_OK,
    BLK_ERR_MEMORY_ALLOCATION,
} Blk_Error;

/*
    Blake2b initialization vector
*/
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908,    // Frac(sqrt(2))
    0xbb67ae8584caa73b,    // Frac(sqrt(3))
    0x3c6ef372fe94f82b,    // Frac(sqrt(5))
    0xa54ff53a5f1d36f1,    // Frac(sqrt(7))
    0x510e527fade682d1,    // Frac(sqrt(11))
    0x9b05688c2b3e6c1f,    // Frac(sqrt(13))
    0x1f83d9abfb41bd6b,    // Frac(sqrt(17))
    0x5be0cd19137e2179     // Frac(sqrt(19))
};

/*
    Blake2b permutation table
*/
static const uint8_t blake2b_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 }, // σ[0]
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }, // σ[1]
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 }, // σ[2]
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 }, // σ[3]
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 }, // σ[4]
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }, // σ[5]
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 }, // σ[6]
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 }, // σ[7]
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 }, // σ[8]
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }  // σ[9]
};

/*
    Constants used in code
*/
#define IV_SIZE 8
#define SIGMA_SIZE 10
#define BLAKE2B_DIGEST_LENGTH 64
#define BLAKE2B_BLOCK_SIZE 12

/*
    blake2b hashing function.
    takes in an input message to hash, its length, an optionnal key and its length.
    outputs a hashlen long hash in output
*/
int Blk_blake2b(uint8_t *output, const uint8_t *input, size_t inputLen, const uint8_t *key, size_t keyLen, size_t hashLen);

#endif

#define BLk_IMPLEMENTATION
#ifdef BLk_IMPLEMENTATION

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int Blk_pad(uint8_t *data, size_t size, size_t blockSize) {
    memset(data + size, 0, blockSize - size);
    return 0;
}

// Rotate right function for 64-bit integers
uint64_t Blk_rotateRight(uint64_t value, int shift) {
    return (value >> shift) | (value << (64 - shift));
}

void Blk_mix(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d, uint64_t x, uint64_t y) {
    *a += *b + x;
    *d = Blk_rotateRight(*d ^ *a, 32);
    *c += *d;
    *b = Blk_rotateRight(*b ^ *c, 24);
    *a += *b + y;
    *d = Blk_rotateRight(*d ^ *a, 16);
    *c += *d;
    *b = Blk_rotateRight(*b ^ *c, 63);
}

void Blk_compress(uint64_t* h, uint8_t* chunk, __uint128_t t, bool isLastBlock) {
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
        
        Blk_mix(&v[0], &v[4], &v[8],  &v[12], m[s[0]], m[s[1]]);
        Blk_mix(&v[1], &v[5], &v[9],  &v[13], m[s[2]], m[s[3]]);
        Blk_mix(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]]);
        Blk_mix(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]]);

        Blk_mix(&v[0], &v[5], &v[10], &v[15], m[s[8]],  m[s[9]]);
        Blk_mix(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
        Blk_mix(&v[2], &v[7], &v[8],  &v[13], m[s[12]], m[s[13]]);
        Blk_mix(&v[3], &v[4], &v[9],  &v[14], m[s[14]], m[s[15]]);
    }

    for (size_t i = 0; i < 8; i++)
    {
        h[i] ^= v[i];
        h[i] ^= v[i + 8];
    }
}

int Blk_blake2b(uint8_t *output, const uint8_t *input, size_t inputLen, const uint8_t *key, size_t keyLen, size_t hashLen) {
    uint64_t h[IV_SIZE];
    size_t cBytesCompressed = 0;
    size_t cBytesRemaining = inputLen;

    memcpy(h, blake2b_IV, sizeof(blake2b_IV));

    h[0] ^= (0x01010000 ^ (keyLen << 8) ^ hashLen);

    uint8_t paddedKey[BLAKE2B_BLOCK_SIZE] = {0};
    if (keyLen > 0) {
        memcpy(paddedKey, key, keyLen);
        Blk_pad(paddedKey, keyLen, BLAKE2B_BLOCK_SIZE);
        cBytesRemaining += BLAKE2B_BLOCK_SIZE;
    }

    uint8_t *combinedInput = malloc(cBytesRemaining);
    if (combinedInput == NULL) {
        return BLK_ERR_MEMORY_ALLOCATION;
    }
    if (keyLen > 0) {
        memcpy(combinedInput, paddedKey, BLAKE2B_BLOCK_SIZE);
        memcpy(combinedInput + BLAKE2B_BLOCK_SIZE, input, inputLen);
    } else {
        memcpy(combinedInput, input, inputLen);
    }

    memset(paddedKey, 0, sizeof(paddedKey));

    while (cBytesRemaining > BLAKE2B_BLOCK_SIZE) {
        uint8_t chunk[BLAKE2B_BLOCK_SIZE];
        memcpy(chunk, combinedInput + (cBytesCompressed), BLAKE2B_BLOCK_SIZE);
        cBytesCompressed += BLAKE2B_BLOCK_SIZE;
        cBytesRemaining -= BLAKE2B_BLOCK_SIZE;

        Blk_compress(h, chunk, cBytesCompressed, 0);
    }

    if (cBytesRemaining > 0) {
        uint8_t finalChunk[BLAKE2B_BLOCK_SIZE] = {0};
        memcpy(finalChunk, combinedInput + cBytesCompressed, cBytesRemaining);
        cBytesCompressed += cBytesRemaining;

        Blk_pad(finalChunk, cBytesRemaining, BLAKE2B_BLOCK_SIZE);
        Blk_compress(h, finalChunk, cBytesCompressed, 1);
    }

    memcpy(output, h, hashLen);
    memset(h, 0, sizeof(h));
    memset(combinedInput, 0, cBytesRemaining);
    free(combinedInput);

    return 0;
}

#endif // BLk2_IMPLEMENTATION