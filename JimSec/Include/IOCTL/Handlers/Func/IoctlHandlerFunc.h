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

/*
* deze moet nog generiek gemaakt worden zodat je een class kan meegeven en de member function van die class kan aanroepen
*/
template<class T> struct IoctlHandlerFunc
{
    template<NTSTATUS(T::* Method)()>
    static NTSTATUS Invoke0(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
    {
        T* instance = static_cast<T*>(context);
        return (instance->*Method)();
    };

    template<NTSTATUS(T::* Method)(PIRP, PIO_STACK_LOCATION)>
    static NTSTATUS Invoke3(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
    {
        T* instance = static_cast<T*>(context);
        return (instance->*Method)(Irp, stack);
    };
};
