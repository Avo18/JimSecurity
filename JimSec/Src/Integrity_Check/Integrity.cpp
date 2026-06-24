//#include <ntddk.h>
//#include <process.h>
//#include <wdf.h>
#include <ntifs.h>
#include "../../../JimSec/Include/Integrity_Check/Common/SHA_256.h"
#include "../../../JimSec/Include/Integrity_Check/Common/Macros.h"
#include "../../../JimSec/Include/Integrity_Check/Types/SHA256_CTX.h"
#include "../../../JimSec/Include/Integrity_Check/Integrity.h"

#define _NO_CRT_STDIO_INLINE

extern "C"
NTSTATUS MmCopyVirtualMemory(PKPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

// De verwachte, ongewijzigde hash van de sectie
const UCHAR EXPECTED_HASH[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

BOOLEAN Integrity_Check::Integrity::Check(ULONG pid, PVOID base, SIZE_T size, BOOLEAN* modified)
{
    UNREFERENCED_PARAMETER(pid);

    SHA256_CTX ctx;
    UCHAR currentHash[32] = { 0 };

    if (modified == NULL || base == NULL || size == 0) {
        return FALSE;
    }

    // Default status instellen
    *modified = FALSE;

    // 1. Initialiseer de SHA-256 context (gebeurt volledig op de kernel stack)
    _sha256.Init(&ctx);

    // 2. Hash de data direct vanuit het geheugenadres
    // WAARSCHUWING: Zorg dat de thread in de juiste procescontext (CR3) zit als 'base' user-mode geheugen is!
    _sha256.Update(&ctx, (const UCHAR*)base, size);

    // 3. Genereer de uiteindelijke hash output
    _sha256.Final(&ctx, currentHash);

    // 4. Vergelijk de berekende hash met onze baseline baseline behulp van kernel's RtlCompareMemory
    if (RtlCompareMemory(currentHash, EXPECTED_HASH, 32) != 32)
    {
        *modified = TRUE; // Er is geknoeid met het geheugen (mismatch)
    }
    else
    {
        *modified = FALSE; // Geheugen is intact
    }

    return TRUE;
}

NTSTATUS ReadProcessMemorySafe(PKPROCESS Process, PVOID SourceAddress, PVOID Buffer, SIZE_T Size)
{
    SIZE_T bytes = 0;

    return MmCopyVirtualMemory(
        Process,
        SourceAddress,
        PsGetCurrentProcess(),
        Buffer,
        Size,
        KernelMode,
        &bytes
    );
}

NTSTATUS CalculateMemoryHash(PKPROCESS process, PVOID baseAddress, SIZE_T size, UCHAR outhash[32])
{
    UNREFERENCED_PARAMETER(outhash);
	UCHAR* buffer = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'buff')); // alloceert geheugen in driver kernel
	if (!buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

    NTSTATUS status = ReadProcessMemorySafe(process, baseAddress, buffer, size);

    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return status;
    }

    Integrity_Check::Integrity* integrityChecker = (Integrity_Check::Integrity*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Integrity_Check::Integrity), 'intg'); // alloceert geheugen in driver kernel
    integrityChecker->Check((ULONG)(ULONG_PTR)PsGetProcessId(process), buffer, size, nullptr);

    ExFreePool(buffer);
    ExFreePool(integrityChecker);

	return STATUS_SUCCESS;
}

BOOLEAN CompareHash(UCHAR a[32], UCHAR b[32])
{
    for (int i = 0; i < 32; i++)
    {
        if (a[i] != b[i])
            return FALSE;
    }
    return TRUE;
}

NTSTATUS CheckModuleIntegrity(ULONG pid, PVOID moduleBase, SIZE_T moduleSize, UCHAR expectedHash[32])
{
    PEPROCESS process = NULL;

    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    UCHAR currentHash[32] = { 0 };

    status = CalculateMemoryHash(process, moduleBase, moduleSize, currentHash);

    ObDereferenceObject(process);

    if (!NT_SUCCESS(status))
        return status;

    if (!CompareHash(currentHash, expectedHash))
    {
        DbgPrint("ANTI-CHEAT: CODE MODIFIED DETECTED!\n");
        return STATUS_ACCESS_DENIED;
    }

    DbgPrint("ANTI-CHEAT: Integrity OK\n");
    return STATUS_SUCCESS;
}