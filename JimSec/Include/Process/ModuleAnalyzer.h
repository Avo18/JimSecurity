#pragma once

#include "Module.h"
#include "../../../JimSec/Include/Kernel/Windows/NtProcess.h"
#include "../../../JimSec/Include/PEB/Types/PEB_LDR_DATA.h"
#include "../../../JimSec/Include/PEB/Types/LDR_DATA_TABLE_ENTRY.h"
#include "Memory.h"

namespace Process
{
    class ModuleAnalyzer
    {
    private:
        static BOOLEAN IsRelativeJmp(unsigned char opcode);
        Memory& _memory;
    public:
        explicit ModuleAnalyzer(Memory& memory);
        static void ExtractCodeSection(PIMAGE_SECTION_HEADER sections, ULONG index, PVOID base, PVOID* buffer, SIZE_T* size);
        static NTSTATUS ScanJumps(PVOID buffer, SIZE_T size, PVOID baseAddress);
        // Functie die controleert of een specifiek adres binnen een legitieme module van de game valt
        BOOLEAN IsAddressInLegitimateModule(PKPROCESS Process, ULONG64 TargetAddress);
    };
}
