#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

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
enum constants {
    IV_SIZE = 8,
    SIGMA_SIZE = 10,
    BLAKE2B_DIGEST_LENGTH = 64,
    BLAKE2B_BLOCK_SIZE = 128
};

/*
    blake2b hashing function.
    takes in an input message to hash, its length, an optionnal key and its length.
    outputs a hashlen long hash in output
*/
int blake2b(uint8_t *output, const uint8_t *input, size_t inputLen, const uint8_t *key, size_t keyLen, size_t hashLen);

#endif