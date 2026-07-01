//#include <ntddk.h>
#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "../../../../JimSec/JimSec/Include/Process/Module.h"
#include "../../../../JimSec/JimSec/Include/Process/Game.h"
#include "../../../../JimSec/JimSec/Include/Process/Enum/Section.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessHelper.h"
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../../JimSec/JimSec/Include/Process/ModuleAnalyzer.h"
#include "../../../../../JimSec/JimSec/Include/Kernel/Windows/NtMemory.h"
#include "../../../../../JimSec/JimSec/Include/Kernel/Windows/NtProcess.h"
#include "../../../../../JimSec/JimSec/Include/PEB/Types/LDR_DATA_TABLE_ENTRY.h"
#include "../../../../../JimSec/JimSec/Include/PEB/Types/PEB_LDR_DATA.h"

#define _NO_CRT_STDIO_INLINE

// new Code


BOOLEAN GetModuleCodeSectionClean(PKPROCESS Process, PVOID BaseAddress, PVOID* outBuffer, SIZE_T* outSize)
{
    if (!Process || !BaseAddress || !outBuffer || !outSize)
        return FALSE;

    *outBuffer = nullptr;
    *outSize = 0;

    Process::Context ctx(Process);

    __try
    {
        ctx.Attach();

        Process::Module module(BaseAddress);

        PIMAGE_NT_HEADERS nt = module.GetNtHeaders();
        if (!nt)
            return FALSE;

        PIMAGE_SECTION_HEADER sections = module.GetSectionHeaders(nt);
        if (!sections)
            return FALSE;

        ULONG index = module.GetSectionIndex(nt, sections, Enum::Section::MachineCode);

        if (index == (ULONG)-1)
            return FALSE;

      /*  Process::ModuleAnalyzer* moduleAnalyser;
        moduleAnalyser->ExtractCodeSection(sections, index, BaseAddress, outBuffer, outSize);*/

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

// Functie die controleert of een specifiek adres binnen een legitieme module van de game valt
BOOLEAN IsAddressInLegitimateModule(PKPROCESS Process, ULONG64 TargetAddress) {
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

//---------------------
//  Integrity check
//  Code Cave Trampolines
//---------------------

// Een globale buffer die de ORIGINELE, SCHONE bytes van de game bevat (bijv. ingelezen van de harde schijf bij opstarten)
// Een array van fixed bytes (bijvoorbeeld: PUSH RBP, MOV RBP, RSP) // __STDCALL calling convention
unsigned char g_CleanImageBuffer[] = { 0x55, 0x48, 0x89, 0xE5 };
SIZE_T g_CleanImageSize = sizeof(g_CleanImageBuffer);

// Functie om de integriteit van de live geheugenpagina te vergelijken met de schone schijf-buffer
VOID VerifyMemoryIntegrity(PVOID TargetVirtualAddress, unsigned char* LiveBuffer, SIZE_T Size) {
    if (!g_CleanImageBuffer) return;

    BOOLEAN IntegrityViolationGrounded = FALSE;

    // Loop byte-voor-byte door de ingelezen pagina heen
    for (SIZE_T i = 0; i < Size; i++) {

        // Vergelijk de live byte in het RAM met de schone byte van de harde schijf
        if (LiveBuffer[i] != g_CleanImageBuffer[i]) {

            ULONG64 ViolationAddress = (ULONG64)TargetVirtualAddress + i;

            // We hebben een modificatie gevonden! Laten we kijken wat er staat.
            if (LiveBuffer[i] == 0xE9) { // Het is een JMP modificatie (Trampoline / Hook)

                // Bereken het doeladres van de JMP om te kijken waar de cheat huist
                int RelativeOffset = *(int*)&LiveBuffer[i + 1];
                ULONG64 TargetAddress = ViolationAddress + 5 + RelativeOffset;

                DbgPrint("[!!!] INTEGRITEITSFOUT: Code modificatie gedetecteerd op %p!\n", (PVOID)ViolationAddress);
                DbgPrint("[!] Verwacht: 0x%02X | Aangetroffen: 0x%02X (JMP naar %llX)\n", g_CleanImageBuffer[i], LiveBuffer[i], TargetAddress);

                IntegrityViolationGrounded = TRUE;
            }
            else if (LiveBuffer[i] == 0xCC) { // Het is een INT 3 (Breakpoint gebruikt door debuggers/cheats)
                DbgPrint("[!!!] INTEGRITEITSFOUT: Debug-breakpoint (INT 3) aangetroffen op %p!\n", (PVOID)ViolationAddress);
                IntegrityViolationGrounded = TRUE;
            }
            else { // Een andere onverwachte wijziging (bijv. aanpassing van variabelen/instructies)
                DbgPrint("[!!!] INTEGRITEITSFOUT: Onbekende geheugenmodificatie op %p! (Verwacht: 0x%02X | Live: 0x%02X)\n",
                    (PVOID)ViolationAddress, g_CleanImageBuffer[i], LiveBuffer[i]);
                IntegrityViolationGrounded = TRUE;
            }
        }
    }

    if (IntegrityViolationGrounded) {
        DbgPrint("[BANNED] Integriteitscontrole gefaald. Het proces is gemanipuleerd.\n");
        // HIER: Activeer ban-logica (bijv. het proces beëindigen via ZwTerminateProcess)
    }
    else {
        DbgPrint("[+] Integriteitscontrole succesvol: Pagina is 100%% identiek aan de schijf.\n");
    }
}


// OLD
// Functie die de instructies (geheugen) van de game scant
NTSTATUS ScanGameMemory(HANDLE GamePid, PVOID TargetVirtualAddress, SIZE_T SizeToRead, SIZE_T A) {
    UNREFERENCED_PARAMETER(A);
    PKPROCESS GameProcess = Process::ProcessHelper::GetByPid(GamePid);
    PKPROCESS CurrentProcess = PsGetCurrentProcess();

    if (!GameProcess) return STATUS_NOT_FOUND;

    PVOID KernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeToRead, 'Anti');
    if (!KernelBuffer) {
        ObDereferenceObject(GameProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T BytesRead = 0;
    NTSTATUS Status = MmCopyVirtualMemory(GameProcess, TargetVirtualAddress, CurrentProcess, KernelBuffer, SizeToRead, KernelMode, &BytesRead);

    if (NT_SUCCESS(Status)) {
        unsigned char* Instructions = (unsigned char*)KernelBuffer;

        // Loop door de buffer heen om te zoeken naar de 0xE9 (JMP) opcode
        for (SIZE_T i = 0; i < BytesRead - 5; i++) {

            // Stap 1: Extraheer de 4-byte relatieve offset die na de 0xE9 komt
            int RelativeOffset = *(int*)&Instructions[i + 1];

            // Stap 2: Bereken waar de JMP daadwerkelijk naartoe springt
            // Formule: Huidig Virtueel Adres + index + 5 bytes (grootte JMP) + Relatieve Offset
            ULONG64 JmpInstructionAddress = (ULONG64)TargetVirtualAddress + i;
            ULONG64 TargetAddress = JmpInstructionAddress + 5 + RelativeOffset;

            if (Instructions[i] == 0xE9) { // Relatieve JMP gedetecteerd
                DbgPrint("[!] JMP gedetecteerd op %p naar doeladres: %llX\n", JmpInstructionAddress, TargetAddress);

                // Stap 3: Controleer of dit doeladres in een bekende library zit
                if (!IsAddressInLegitimateModule(GameProcess, TargetAddress)) {
                    DbgPrint("[!!!] CHEAT DETECTIE: JMP springt naar een ONBEKENDE/EXTERNE regio! Adres: %llX\n", TargetAddress);
                    // HIER KUN JE DE SPELER BANNEN OF DE GAME CRASHEN
                }
            }
        }
        // integrity check
        VerifyMemoryIntegrity(TargetVirtualAddress, Instructions, BytesRead);
    }

    ExFreePoolWithTag(KernelBuffer, 'Anti');
    ObDereferenceObject(GameProcess);
    return Status;
}





// NEW
NTSTATUS ScanGameMemory(HANDLE GamePid, PVOID TargetVirtualAddress, SIZE_T SizeToRead)
{
    PKPROCESS gameProcess = Process::ProcessHelper::GetByPid(GamePid);
    if (!gameProcess)
        return STATUS_NOT_FOUND;

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeToRead, 'scnA');
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T bytesRead = 0;

    Process::Context context(gameProcess);
    Process::Memory memory(context);

    NTSTATUS status = memory.Read(gameProcess, TargetVirtualAddress, &buffer, SizeToRead, bytesRead);

    if (!NT_SUCCESS(status))
    {
        ExFreePool(buffer);
        return status;
    }

    Process::ModuleAnalyzer modelAnalyser(memory);
    status = modelAnalyser.ScanJumps(buffer, bytesRead, TargetVirtualAddress);

    ExFreePool(buffer);

    return status;
}
