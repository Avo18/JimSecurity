#pragma once 
#include <ntddk.h>

//// SHA-256 Context structuur
typedef struct {
    UCHAR data[64];
    ULONG datalen;
    ULONGLONG bitlen[1]; // ULONGLONG is schoner in x64 Windows Kernel dan ULONG long
    ULONG state[8];
} SHA256_CTX;