#pragma once
#include "Module.h"
#include "../../../../../JimSec/JimSec/Include/Kernel/Windows/NtMemory.h"
#include "../../../JimSec/Include/Process/ProcessContext.h"

namespace Process
{
    class Memory
    {
    private:
        PEPROCESS _process;
        Context& _context;
    public:
        explicit Memory(PEPROCESS process);
        explicit Memory(Context& context);
        Context GetContext();
        static NTSTATUS Read(PEPROCESS process, PVOID address, PVOID* buffer, SIZE_T size, SIZE_T bytesRead = 0);
    };
}
