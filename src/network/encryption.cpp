#include "../../include/common.h"

// Simple XOR encryption (replace with AES for production)
void XorEncrypt(BYTE* data, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

void XorDecrypt(BYTE* data, SIZE_T size, BYTE key) {
    XorEncrypt(data, size, key); // XOR is symmetric
}