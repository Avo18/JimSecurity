#include "IOCTL.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "Include/Shared_Protocol/Auth.h"
#include "Include/Sessions/Auth.h"
#include "Authentication.cpp"
#include "Include/RSA/MemoryKey.h"

PDEVICE_OBJECT gDeviceObject = NULL;
extern DRIVER_SESSION gSession = {};

typedef struct _AUTH_REQUEST {
    ULONG Magic;
    ULONG ClientId;
} AUTH_REQUEST;

BOOLEAN gAuthenticated = FALSE;

RSA::MemoryKey* _memoryKey;

BOOLEAN ValidateCaller(PVOID buffer, ULONG size)
{
    if (!buffer || size < sizeof(AUTH_REQUEST))
        return FALSE;

    AUTH_REQUEST* req = (AUTH_REQUEST*)buffer;

    if (req->Magic != DRIVER_MAGIC)
        return FALSE;

    return TRUE;
}

BOOLEAN VerifyClient(BYTE* signature)
{
    BOOLEAN result = TRUE;
    //result = VerifySignature(PublicKey, gSession.Challenge, signature);
    UNREFERENCED_PARAMETER(signature);

    return result;

}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

 //   // achter het herwerken van switch case deze code enablen. 
	//IOCTL::IoControlList ioControlList;
 //   ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
 //   IOCTL_ENTRY* entry = ioControlList.FindHandler(ioctlCode);
 //   if (entry != NULL)
 //   {
 //       status = entry->Handler(entry->Context, Irp, stack);
 //   }
 //   else
 //   {
 //       status = STATUS_INVALID_DEVICE_REQUEST;
 //   }

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_LOAD_KEY:
    {
        PUCHAR input = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;

        status = _memoryKey->LoadPublicKey(input, inputSize);
        
        break;
    }
    case IOCTL_AUTH:
    {
        /*       Signature = RSA_SIGN(
                   PrivateKey,
                   Challenge
               );*/

               /*    if (VerifyClient(Signature))
                     {
                         gSession.Authenticated = TRUE;
                     }
                     else
                     {
                         gSession.Authenticated = FALSE;
                     }*/
        if (!gSession.Authenticated)
        {
            return STATUS_ACCESS_DENIED;
        }

        if (!ValidateCaller(Irp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength))
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        gAuthenticated = TRUE;
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_AUTH_START:
    {
        AUTH_CHALLENGE response;
        RtlZeroMemory(&response, sizeof(AUTH_CHALLENGE));

        Authentication auth = Authentication();
        auth.GenerateChallenge(response.Challenge);

        memcpy((gSession.Challenge), (response.Challenge), (32));

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &response, sizeof(response));

        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_PING:
    {
        if (!gAuthenticated)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        //if (!IsHvciEnabled())
        //{
            //DbgPrint("HVCI NOT enabled - security reduced mode\n");
            //status = STATUS_ACCESS_DENIED;
            //break;
        //}

        DbgPrint("Ping received from authenticated client\n");
        status = STATUS_SUCCESS;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    //// CRUCIAL: Verwijder de callbacks bij het afsluiten van de driver!
    //// Als je dit vergeet, blijft Windows naar lege functies wijzen en krijg je een BSOD.
    //PsRemoveCreateThreadNotifyRoutine(AntiCheatThreadNotifyRoutine);
    //PsSetCreateProcessNotifyRoutine(AntiCheatProcessNotifyRoutine, TRUE); // TRUE betekent verwijderen

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);

    _memoryKey->Init();

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &gDeviceObject
    );

    if (!NT_SUCCESS(status))
        return status;

    IoCreateSymbolicLink(&symLink, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    //// Scan zodra er een nieuw proces start word er gekeken of er een cheat-injector opgestart word
    //status = PsSetCreateProcessNotifyRoutine(AntiCheatProcessNotifyRoutine, FALSE); // FALSE betekent toevoegen
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Fout bij registreren proces callback: 0x%X\n", status);
    //    return status;
    //}

    //// Scan zodra er een nieuwe thread wordt aangemaakt binnen het game-proces. 
    //// Cheats maken vaak een nieuwe thread aan om hun code te runnen. Dat is hét moment om te scannen.
    //status = PsSetCreateThreadNotifyRoutine(AntiCheatThreadNotifyRoutine);
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Fout bij registreren thread callback: 0x%X\n", status);
    //    // Ruim de al geregistreerde proces-callback op
    //    PsSetCreateProcessNotifyRoutine(AntiCheatProcessNotifyRoutine, TRUE);
    //    return status;
    //}

    return STATUS_SUCCESS;
}


//#include <ntddk.h>
//#include "SecurityDriver.h"
//
//
//UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SecurityDriver");
//UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(L"\\DosDevices\\SecurityDriver");
//
//VOID DriverUnload(PDRIVER_OBJECT DriverObject)
//{
//    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\DosDevices\\SecurityDriver");
//
//    IoDeleteSymbolicLink(&sym);
//    IoDeleteDevice(DriverObject->DeviceObject);
//
//    DbgPrint("SecurityDriver unloaded\n");
//}
//
//NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//    UNREFERENCED_PARAMETER(DeviceObject);
//
//    Irp->IoStatus.Status = STATUS_SUCCESS;
//    Irp->IoStatus.Information = 0;
//
//    IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//    return STATUS_SUCCESS;
//}
//
//NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//    UNREFERENCED_PARAMETER(DeviceObject);
//    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
//    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
//
//    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
//
//    if (code == IOCTL_SECURITY_PING && ValidateCaller())
//    {
//        DbgPrint("Security ping received\n");
//        status = STATUS_SUCCESS;
//    }
//
//    Irp->IoStatus.Status = status;
//    Irp->IoStatus.Information = 0;
//
//    IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//
//    return status;
//}
//
//BOOLEAN ValidateCaller()
//{
//    PEPROCESS process;
//    process = PsGetCurrentProcess();
//
//    if (!process)
//        return FALSE;
//
//    const char* name = (const char*)PsGetProcessImageFileName(process);
//
//    if (_stricmp(name, "Security.Native.dll") == 0)
//    {
//        return TRUE;
//    }
//    return FALSE;
//}
//
//
//
//// dit is de entry point van de driver, hier worden de functies geregistreerd en het device object aangemaakt
//// zoals Main in een normale applicatie
//extern "C"
//NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
//{
//
//    UNREFERENCED_PARAMETER(RegistryPath);
//
//    DriverObject->DriverUnload = DriverUnload;
//
//	    // Driver object word geregistreerd voor create en close, beide wijzen naar dezelfde functie
//        DriverObject->MajorFunction[IRP_MJ_CREATE] =  DeviceCreateClose;
//        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
//        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
//
//                PDEVICE_OBJECT deviceObject;
//
//                NTSTATUS status =
//                    IoCreateDevice(
//                        DriverObject,
//                        0,
//                        &DeviceName,
//                        FILE_DEVICE_UNKNOWN,
//                        0,
//                        FALSE,
//                        &deviceObject
//                    );
//
//                if (!NT_SUCCESS(status))
//                    return status;
//                
//                status = IoCreateSymbolicLink(&SymbolicName, &DeviceName);
//
//                if (!NT_SUCCESS(status))
//                {
//                    IoDeleteDevice(deviceObject);
//                    return status;
//                }
//
//                DbgPrint("SecurityDriver loaded\n");
//
//                return STATUS_SUCCESS;
//}