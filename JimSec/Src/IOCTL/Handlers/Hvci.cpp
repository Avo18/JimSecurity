#include <ntddk.h>
#include "../../../Include/IOCTL/Handlers/Hvci.h"

// kijkt of HVCI aan staat.
// hvci is een hypervisor die bepaalde beveiligingsfuncties biedt, zoals het isoleren van kritieke systeemprocessen en het voorkomen van bepaalde soorten aanvallen.
// Windows Security -> Device Security -> Core Isolation -> Memory Integrity aan (herstart pc)
namespace IOCTL_Handlers
{
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemCodeIntegrityInformation = 103
    } SYSTEM_INFORMATION_CLASS;

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
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x02

	NTSTATUS Hvci::IsEnabled(PIRP irp, PIO_STACK_LOCATION stack)
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
}