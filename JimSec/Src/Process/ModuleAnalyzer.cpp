#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../JimSec/JimSec/Include/Process/Module.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Process/ModuleAnalyzer.h"
#include "../../../JimSec/Include/Kernel/Windows/NtProcess.h"
#include "../../../JimSec/Include/PEB/Types/PEB_LDR_DATA.h"
#include "../../../JimSec/Include/PEB/Types/LDR_DATA_TABLE_ENTRY.h"

namespace Process
{
    ModuleAnalyzer::ModuleAnalyzer(Memory& memory)
        : _memory(memory)
    {
    }

    BOOLEAN ModuleAnalyzer::IsRelativeJmp(unsigned char opcode)
    {
        return opcode == 0xE9;
    }

    VOID ModuleAnalyzer::ExtractCodeSection(PIMAGE_SECTION_HEADER sections, ULONG index, PVOID base, PVOID* buffer, SIZE_T* size)
    {
        if (!sections || !buffer || !size || index == (ULONG)-1)
            return;

        *buffer = (PUCHAR)base + sections[index].VirtualAddress;
        *size = sections[index].Misc.VirtualSize;
    }

    NTSTATUS ModuleAnalyzer::ScanJumps(PVOID buffer, SIZE_T size, PVOID baseAddress)
    {
        unsigned char* bytes = (unsigned char*)buffer;

        for (SIZE_T i = 0; i < size - 5; i++)
        {
            if (IsRelativeJmp(bytes[i]))
                continue;

            int relOffset = *(int*)&bytes[i + 1];

            ULONG64 instrAddr = (ULONG64)baseAddress + i;
            ULONG64 target = instrAddr + 5 + relOffset;

            DbgPrint("[!] JMP detected at %p -> %llX\n", (PVOID)instrAddr, target);

            //if (!IsAddressInLegitimateModule(_memory.GetContext().GetProcess(), target)) {
            //    DbgPrint("[!!!] CHEAT DETECTIE: JMP springt naar een ONBEKENDE/EXTERNE regio! Adres: %llX\n", target);
            //}
        }

        return STATUS_SUCCESS;
    }

    // Functie die controleert of een specifiek adres binnen een legitieme module van de game valt
    BOOLEAN ModuleAnalyzer::IsAddressInLegitimateModule(PKPROCESS Process, ULONG64 TargetAddress) {
        PVOID Peb = PsGetProcessPeb(Process);
        if (!Peb) return FALSE;

        // Microsoft specifieke offset voor Ldr in PEB (x64 Windows 10/11)
        PPEB_LDR_DATA Ldr = *(PPEB_LDR_DATA*)((PCHAR)Peb + 0x18);
        if (!Ldr) return FALSE;

        // Attach aan de procescontext om de user-mode PEB-lijst veilig te kunnen lezen
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);

        BOOLEAN FoundValidModule = FALSE;
        PLIST_ENTRY Head = &Ldr->InLoadOrderModuleList;
        PLIST_ENTRY Curr = Head->Flink;

        // Loop door alle geladen libraries (.dll / .exe) van de game heen
        while (Curr != Head) {
            PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            ULONG64 ModuleStart = (ULONG64)Module->DllBase;
            ULONG64 ModuleEnd = ModuleStart + Module->SizeOfImage;

            // Controleer of het berekende JMP-doeladres binnen deze library valt
            if (TargetAddress >= ModuleStart && TargetAddress < ModuleEnd) {
                // Optioneel: Hier kun je controleren of de module naam 'DiscordHook64.dll' is etc.
                DbgPrint("[+] Adres bevindt zich in legitieme module: %wZ\n", &Module->BaseDllName);
                FoundValidModule = TRUE;
                break;
            }

            Curr = Curr->Flink;
        }

        KeUnstackDetachProcess(&ApcState);
        return FoundValidModule;
    }


}