#include <ntddk.h>
#include <wdf.h>
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Auth.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/PublicKey.h"

using namespace IOCTL_Handlers;

typedef NTSTATUS(*PIOCTL_HANDLER)(
    void* Context,
    PIRP Irp,
    PIO_STACK_LOCATION stack
    );
struct IOCTL_ENTRY
{
    ULONG Ioctl;
    PIOCTL_HANDLER Handler;
    void* Context;
};

template<typename T> struct IoctlHandler
{
    template<NTSTATUS(T::* Method)(PIRP, PIO_STACK_LOCATION)>
    static NTSTATUS Invoke(void* context, PIRP Irp, PIO_STACK_LOCATION stack)
    {
        T* instance = static_cast<T*>(context);
        return (instance->*Method)(Irp, stack);
    }
};

#define IOCTL_COUNT 1

namespace IOCTL
{
    class IoControlList
    {
    private:
        IOCTL_Handlers::PublicKey publicKey;

        IOCTL_ENTRY g_Table[IOCTL_COUNT];
    public:
        IoControlList()
            : publicKey(&RSA::MemoryKey())
        {
            g_Table[0] = { IOCTL_LOAD_KEY, IoctlHandler<IOCTL_Handlers::PublicKey>::Invoke<&IOCTL_Handlers::PublicKey::Load>, &publicKey };
        }
        PIOCTL_HANDLER FindHandler(ULONG ioctl);
    };
}


/*
auto entry = FindHandler(Ioctl);

if(entry)
{
    return entry->Handler(
        entry->Context,
        Irp,
        stack
    );
}
*/