#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"

namespace Process
{
    Memory::Memory(PEPROCESS process)
    {
        _process = process;
    }

    Memory::Memory(Context& context)
        : _context(context)
    {

    }

    Context Memory::GetContext()
    {
        return _context;
    }

    NTSTATUS Memory::Read(PEPROCESS process, PVOID address, PVOID* buffer, SIZE_T size, SIZE_T bytesRead = 0)
    {
        if (!process || !address || !buffer)
            return STATUS_INVALID_PARAMETER;

        return MmCopyVirtualMemory(
            process,
            address,
            PsGetCurrentProcess(),
            buffer,
            size,
            KernelMode,
            &bytesRead
        );
    }
}