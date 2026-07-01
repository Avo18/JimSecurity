//------------------------
// Process environment Block
//------------------------
#pragma once
#include <ntddk.h>

// Handmatige structuren voor PEB-traversal (om geladen libraries te vinden)
typedef struct PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;