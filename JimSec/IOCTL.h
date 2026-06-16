#pragma once
#include <ntddk.h>

//IOCTL = Input & output control richting drivers, hiermee kunnen gebruikersmode applicaties communiceren met kernelmode drivers.
#define DEVICE_NAME L"\\Device\\JimSecurity"
#define SYMLINK_NAME L"\\DosDevices\\JimSecurity"

#define IOCTL_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_MAGIC 0x4A534543 // "JSEC"