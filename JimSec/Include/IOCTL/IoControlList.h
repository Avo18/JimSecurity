#pragma once
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/PublicKey.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/Func/IoctlHandlerFunc.h"

#define IOCTL_COUNT 5
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

