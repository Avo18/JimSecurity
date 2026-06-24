#include <ntddk.h>
// enkel voor heaps gebruiken, long living objects

#define JIMS_POOL_TAG 'mciJ'

void* __cdecl operator new(size_t size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, JIMS_POOL_TAG);
}

void __cdecl operator delete(void* ptr) {
    if (ptr) {
        ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
    }
}

void __cdecl operator delete(void* ptr, size_t size) {
    UNREFERENCED_PARAMETER(size);
    if (ptr) {
        ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
    }
}