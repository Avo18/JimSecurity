#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "../../../../JimSec/JimSec/Include/Process/Enum/Section.h"

namespace Process
{
    class Module
    {
    public:
        Module(PVOID baseAddress);
        ~Module();
        PIMAGE_NT_HEADERS GetNtHeaders() const;
        PIMAGE_SECTION_HEADER GetSectionHeaders(PIMAGE_NT_HEADERS nt) const;
        PIMAGE_SECTION_HEADER Module::GetSectionHeaders() const;
        ULONG GetSectionIndex(PIMAGE_NT_HEADERS nt, PIMAGE_SECTION_HEADER sec, Enum::Section section);
        ULONG Module::GetSectionIndex(Enum::Section section);
    private:
        PVOID _baseAddress;
    };
}