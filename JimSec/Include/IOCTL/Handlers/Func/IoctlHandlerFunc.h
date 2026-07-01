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
template<typename T> struct IoctlHandlerFunc
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










//template<typename T> struct IoctlHandlerFunc
//{
//    template<NTSTATUS(T::* Method)()>
//    static NTSTATUS Invoke0(void* context)
//    {
//        T* instance = static_cast<T*>(context);
//        return (instance->*Method)();
//    };
//
//    template<NTSTATUS(T::* Method)(PIRP, PIO_STACK_LOCATION)>
//    static NTSTATUS Invoke3(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
//    {
//        T* instance = static_cast<T*>(context);
//        return (instance->*Method)(Irp, stack);
//    };
//};

//template<typename T>
//struct IoctlHandlerFunc
//{
//    template<typename... Args, NTSTATUS(T::* Method)(Args...)>
//    static NTSTATUS Invoke(void* context, Args... args)
//    {
//        T* instance = static_cast<T*>(context);
//        return (instance->*Method)(args...);
//    }
//    template<NTSTATUS(T::* Method)(PIRP, PIO_STACK_LOCATION)>
//    static NTSTATUS IoctlThunk(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
//    {
//        T* obj = static_cast<T*>(context);
//        return (obj->*Method)(Irp, stack);
//    }
//};

//template<typename T> struct IoctlHandlerFunc
//{
//    template<typename Ret, typename... Args>
//    static Ret Invoke(void* context, Ret(T::* method)(Args...), Args... args)
//    {
//        T* instance = static_cast<T*>(context);
//        return (instance->*method)(args...);
//    }
//};