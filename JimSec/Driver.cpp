#include "IOCTL.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "Include/Shared_Protocol/Auth.h"
#include "Include/Sessions/Auth.h"
#include "Include/RSA/MemoryKey.h"

PDEVICE_OBJECT gDeviceObject = NULL;

NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    // achter het herwerken van switch case deze code enablen. 
	IOCTL::IoControlList ioControlList;
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    IOCTL_ENTRY* entry = ioControlList.FindHandler(ioctlCode);
    if (entry != NULL)
    {
        status = entry->Handler(entry->Context, irp, stack);
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;

    IoCompleteRequest(irp, IO_NO_INCREMENT);
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

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);

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

    return STATUS_SUCCESS;
}
