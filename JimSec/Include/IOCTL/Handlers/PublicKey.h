#pragma once
#include "..\..\..\..\..\JimSec\JimSec\Include\RSA\MemoryKey.h"

namespace IOCTL_Handlers
{
    class PublicKey
    {
    private:
        RSA::MemoryKey* _memoryKey;
    public:
        PublicKey(RSA::MemoryKey* memoryKey);
        NTSTATUS Load(PIRP irp, PIO_STACK_LOCATION stack);
    };
}
