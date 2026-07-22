#pragma once
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/PublicKey.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/Func/IoctlHandlerFunc.h"

#define IOCTL_COUNT 4
namespace IOCTL
{
    class IoControlList
    {
    private:
        IOCTL_Handlers::PublicKey* publicKey;

        IOCTL_ENTRY _Table[IOCTL_COUNT];
    public:
        IoControlList();
        IOCTL_ENTRY* FindHandler(ULONG ioctl);
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