//#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#define _NO_CRT_STDIO_INLINE

enum class Section
{
    MachineCode,
};

static constexpr const char* ToString[] =
{
    ".txt",
};

constexpr const char* GetMessage(Section section)
{
    return ToString[(int)section];
}

class Scanner
{

};
class GameProcess
{

};
// Reworked code:
class Module
{
private:
    PKPROCESS _process;
    PVOID _baseAddress;
    KAPC_STATE state;
public:
    Module(PKPROCESS process, PVOID baseAddress);
    ~Module();
    PIMAGE_NT_HEADERS GetPE_File();
    PIMAGE_SECTION_HEADER GetSectionHeaders(PIMAGE_NT_HEADERS pe_file);
    ULONG GetIndexSectionHeader(PIMAGE_NT_HEADERS PE_Header, PIMAGE_SECTION_HEADER sectionHeader, Section section);
    VOID GetModuleCodeSection(PIMAGE_SECTION_HEADER sectionHeaders, ULONG sectionHeaderIndex,__out PVOID* buffer, __out SIZE_T* size);
    
    VOID BUILD(__out PVOID* buffer, __out SIZE_T* size);
};

Module::Module(PKPROCESS process, PVOID baseAddress)
{
    this->_process = process;
    this->_baseAddress = baseAddress;
    KeStackAttachProcess(this->_process, &state);
}

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
PIMAGE_NT_HEADERS Module::GetPE_File()
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)this->_baseAddress;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)this->_baseAddress + dos->e_lfanew);
    return nt;
}

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
PIMAGE_SECTION_HEADER Module::GetSectionHeaders(PIMAGE_NT_HEADERS pe_file)
{
    return IMAGE_FIRST_SECTION(pe_file);
}

ULONG Module::GetIndexSectionHeader(PIMAGE_NT_HEADERS PE_Header, PIMAGE_SECTION_HEADER sectionHeader, Section section)
{
    for (int i = 0; i < PE_Header->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(sectionHeader[i].Name, ToString[(int)section], 5) == 0)
        {
            return i;
        }
    }
    return NULL;
}

VOID Module::GetModuleCodeSection(PIMAGE_SECTION_HEADER sectionHeaders, ULONG sectionHeaderIndex,  __out PVOID* buffer, __out SIZE_T* size)
{
    *buffer = (PUCHAR)this->_baseAddress + sectionHeaders[sectionHeaderIndex].VirtualAddress;
    *size = sectionHeaders[sectionHeaderIndex].Misc.VirtualSize;
}

VOID Module::BUILD(__out PVOID* buffer, __out SIZE_T* size)
{
    PIMAGE_NT_HEADERS pe_file = GetPE_File();
    PIMAGE_SECTION_HEADER sectionHeaders = GetSectionHeaders(pe_file);
    ULONG sectionHeaderIndex = GetIndexSectionHeader(pe_file, sectionHeaders, Section::MachineCode);
    PVOID* buffer; SIZE_T* size;

    GetModuleCodeSection(sectionHeaders, sectionHeaderIndex, buffer, size);


}

Module::~Module()
{
    KeUnstackDetachProcess(&state);
}



// OLD code

BOOLEAN GetModuleCodeSection(PKPROCESS Process, PVOID BaseAddress, PVOID* outBuffer, SIZE_T* outSize)
{
    KAPC_STATE state = {};
    
    KeStackAttachProcess(Process, &state);

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)BaseAddress;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + dos->e_lfanew);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (memcmp(section[i].Name, ".text", 5) == 0)
            {
                *outBuffer = (PUCHAR)BaseAddress + section[i].VirtualAddress;
                *outSize = section[i].Misc.VirtualSize;

                KeUnstackDetachProcess(&state);
                return TRUE;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&state);
        return FALSE;
    }

    KeUnstackDetachProcess(&state);
    return FALSE;
}

// Handmatige declaratie van de semi-gedocumenteerde kernel functie
extern "C" NTSTATUS MmCopyVirtualMemory(
    PKPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

// Helper-functie om het PEPROCESS van de game te vinden via het Process ID (PID)
PKPROCESS GetProcessByPid(HANDLE ProcessId) {
    PKPROCESS Process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
        return Process;
    }
    return NULL;
}

//------------------------
// Process environment Block
//------------------------

// Handmatige structuren voor PEB-traversal (om geladen libraries te vinden)
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Omdat PEB ongedocumenteerd is in de kernel header, halen we deze handmatig op via PsGetProcessPeb
extern "C" PVOID PsGetProcessPeb(PKPROCESS Process);

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

// Functie die de instructies (geheugen) van de game scant
NTSTATUS ScanGameMemory(HANDLE GamePid, PVOID TargetVirtualAddress, SIZE_T SizeToRead) {
    PEPROCESS GameProcess = GetProcessByPid(GamePid);
    PEPROCESS CurrentProcess = PsGetCurrentProcess();

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
