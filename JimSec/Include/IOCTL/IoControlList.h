#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Auth.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/PublicKey.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/Func/IoctlHandlerFunc.h"

using namespace IOCTL_Handlers;


#define IOCTL_COUNT 1

namespace IOCTL
{
    class IoControlList
    {
    private:
        IOCTL_Handlers::PublicKey* publicKey;

        IOCTL_ENTRY g_Table[IOCTL_COUNT];
    public:
        IoControlList();
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