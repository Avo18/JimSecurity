#pragma once

#include "../../../SecurityDriver.h"

namespace IOCTL_Types
{
    typedef struct PUBLIC_KEY
    {
        PUCHAR Buffer;     // pointer naar allocated kernel memory
        ULONG Size;        // huidige grootte
        ULONG Hash;        // optional integrity check
    };
}
extern IOCTL_Types::PUBLIC_KEY gPublicKey;