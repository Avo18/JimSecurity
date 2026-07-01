#pragma once

namespace Process
{
    class Memory;
    class ModuleAnalyzer
    {
    private:
        static BOOLEAN IsRelativeJmp(unsigned char opcode);
        Memory& _memory;
    public:
        explicit ModuleAnalyzer(Memory& memory);
        void ExtractCodeSection(PIMAGE_SECTION_HEADER sections, ULONG index, PVOID base, PVOID* buffer, SIZE_T* size);
        NTSTATUS ScanJumps(PVOID buffer, SIZE_T size, PVOID baseAddress);
        // Functie die controleert of een specifiek adres binnen een legitieme module van de game valt
        BOOLEAN IsAddressInLegitimateModule(PKPROCESS Process, ULONG64 TargetAddress);
    };
}
