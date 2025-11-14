#include "../../include/common.h"

std::string XorString(const char* str, size_t len, int key) {
    std::string result;
    result.reserve(len);
    
    for (size_t i = 0; i < len; i++) {
        result += (char)(str[i] ^ (key + i));
    }
    
    return result;
}

void RandomizeString(char* str, size_t len) {
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; i++) {
        str[i] = (char)(rand() % 26 + 'a');
    }
}