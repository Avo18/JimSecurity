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
        PVOID m_baseAddress;
    };
}


// cpp file nog te verplaatsen
Process::Module::Module(PVOID baseAddress)
{
    m_baseAddress = baseAddress;
};

    Process::Module::~Module()
    {
    };

    /// <summary>
    /// NT betekend van windows NT
    /// PE file = Elk process heeft een Portable Executable waar informatie staat hoe het program geladen moet worden
    /// 
    /// PIMAGE_NT_HEADERS
    /// P     = Pointer
    // IMAGE  = PE image structuur
    //  NT    = Windows NT executable format
    //HEADERS = header informatie
    /// </summary>
    /// <returns>PIMAGE_NT_HEADERS</returns>
    PIMAGE_NT_HEADERS Process::Module::GetNtHeaders() const
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)this->m_baseAddress;

        if (!dos || dos->e_lfanew == 0)
            return nullptr;

        return (PIMAGE_NT_HEADERS)((PUCHAR)this->m_baseAddress + dos->e_lfanew);
    };

    /// <summary>
    /// Sectie = Segment binnen windows executable (vb: .text, .data, .rdata, ...)
    /// 
    /// PIMAGE_SECTION_HEADER
    /// P = Pointer
    /// IMAGE = PE Image structuur
    /// NT = Windows NT executable
    /// 
    /// </summary>
    /// <returns></returns>
    PIMAGE_SECTION_HEADER Process::Module::GetSectionHeaders(PIMAGE_NT_HEADERS nt) const
    {
        if (!nt)
            return nullptr;

        return IMAGE_FIRST_SECTION(nt);
    };
    PIMAGE_SECTION_HEADER Process::Module::GetSectionHeaders() const
    {
		PIMAGE_NT_HEADERS nt = GetNtHeaders();
        if (!nt)
            return nullptr;

        return IMAGE_FIRST_SECTION(nt);
    };

    ULONG Process::Module::GetSectionIndex(PIMAGE_NT_HEADERS nt, PIMAGE_SECTION_HEADER sectionHeader, Enum::Section section)
    {
        if (!nt || !sectionHeader)
            return (ULONG)-1;

        for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (memcmp(sectionHeader[i].Name, Enum::ToString[(int)section], 5) == 0)
            {
                return i;
            }
        }

        return (ULONG)-1;
    };
    ULONG Process::Module::GetSectionIndex(Enum::Section section)
    {
		PIMAGE_NT_HEADERS nt = GetNtHeaders();
		PIMAGE_SECTION_HEADER sectionHeader = GetSectionHeaders(nt);
        if (!nt || !sectionHeader)
            return (ULONG)-1;

        for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (memcmp(sectionHeader[i].Name, Enum::ToString[(int)section], 5) == 0)
            {
                return i;
            }
        }

        return (ULONG)-1;
    };