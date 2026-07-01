#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../../JimSec/JimSec/Include/Kernel/Windows/NtMemory.h"
#include "../../../JimSec/Include/Process/ProcessContext.h"


namespace Process
{
    //Memory::Memory(PKPROCESS& process)
    //    : _process(process)
    //{
    //}

    Memory::Memory(Context& context)
        : _context(context)
    {

    }

    Context& Memory::GetContext()
    {
        return _context;
    }

    NTSTATUS Memory::Read(PKPROCESS process, PVOID address, PVOID* buffer, SIZE_T size, SIZE_T bytesRead)
    {
        if (!process || !address || !buffer)
            return STATUS_INVALID_PARAMETER;
        PKPROCESS CurrentProcess = PsGetCurrentProcess();
        return MmCopyVirtualMemory(
            process,
            address,
            CurrentProcess,
            buffer,
            size,
            KernelMode,
            &bytesRead
        );
    }
}