#pragma once
#include "../../RSA/MemoryKey.h"

using namespace RSA;

namespace IOCTL_Handlers
{
    class PublicKey
    {
    private:
        RSA::MemoryKey* _memoryKey;
    public:
        PublicKey(RSA::MemoryKey* memoryKey);
        NTSTATUS Load(PIRP Irp, PIO_STACK_LOCATION stack);
    };
}
