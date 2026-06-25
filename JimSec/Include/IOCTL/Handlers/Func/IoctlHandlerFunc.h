#pragma once
#include <ntddk.h>
#include <wdf.h>

typedef NTSTATUS(*PIOCTL_HANDLER)(void* Context, PIRP Irp, PIO_STACK_LOCATION stack);

struct IOCTL_ENTRY
{
    ULONG Ioctl;
    PIOCTL_HANDLER Handler;
    void* Context;
};

template<typename T> struct IoctlHandlerFunc
{
    template<NTSTATUS(T::* Method)(PIRP, PIO_STACK_LOCATION)>
    static NTSTATUS Invoke(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
    {
        T* instance = static_cast<T*>(context);
        return (instance->*Method)(Irp, stack);
    }
};