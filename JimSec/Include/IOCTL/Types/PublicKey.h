#include "../../../SecurityDriver.h"

namespace IOCTL_Types
{
    typedef struct _PUBLIC_KEY
    {
        PUCHAR Buffer;     // pointer naar allocated kernel memory
        ULONG Size;        // huidige grootte
        ULONG Hash;        // optional integrity check
    } _PUBLIC_KEY;
}