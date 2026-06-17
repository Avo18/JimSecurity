#include "HVCI.h"
#include <ntddk.h>

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
    );

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

#define SystemCodeIntegrityInformation 103

BOOLEAN IsHvciEnabled()
{
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");

    ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);

    if (!ZwQuerySystemInformation)
        return FALSE;

    SYSTEM_CODEINTEGRITY_INFORMATION info;
    RtlZeroMemory(&info, sizeof(info));

    info.Length = sizeof(info);

    NTSTATUS status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemCodeIntegrityInformation, &info, sizeof(info), NULL);

    if (!NT_SUCCESS(status))
        return FALSE;

    return (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
}