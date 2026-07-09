#pragma once
#include <ntddk.h>
#define JIMS_POOL_TAG 'mciJ'


template<typename T, typename... Args> T* AllocateObject(Args&&... args)
{
    void* memory = Allocate(sizeof(T));
    if (!memory)
        return nullptr;

    return new(memory) T(Forward<Args&&>(args)...);
}

template<typename T> inline T&& Forward(T&& arg)
{
    return static_cast<T&&>(arg);
}

template<typename T> void FreeObject(T* object)
{
    if (!object) return;
    //object->~T();
    static_cast<T*>(object)->~T();
    ExFreePoolWithTag(object, JIMS_POOL_TAG);
}

inline void* operator new(size_t, void* address)
{
    return address;
}

inline void* __cdecl Allocate(size_t size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, JIMS_POOL_TAG);
}

/*
* comoiler genereert zelf een deleting destructor dus we moeten operator delete implementeren anders krijg je een linker error 'scalar deleting destructor'
* FreeObject heeft een decontructor die decontrcutor zoekt achterliggend achter delete maar die moet overschreven worden anders gebruikt die STL delete operator 
* en die is niet beschikbaar in kernel mode
*/
inline void operator delete(void* ptr)
{
    ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
}

inline void operator delete(void* ptr, size_t)
{
    ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
}

//void __cdecl operator delete(void* ptr, size_t size) {
//        UNREFERENCED_PARAMETER(size);
//        if (ptr) {
//            ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
//        }
//    }

//// enkel voor heaps gebruiken, long living objects
//
//#define JIMS_POOL_TAG 'mciJ'
//
//namespace Util
//{
//    void* __cdecl operator new(size_t size) {
//        return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, JIMS_POOL_TAG);
//    }
//
//    void __cdecl operator delete(void* ptr) {
//        if (ptr) {
//            ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
//        }
//    }
//
//    void __cdecl operator delete(void* ptr, size_t size) {
//        UNREFERENCED_PARAMETER(size);
//        if (ptr) {
//            ExFreePoolWithTag(ptr, JIMS_POOL_TAG);
//        }
//    }
//}