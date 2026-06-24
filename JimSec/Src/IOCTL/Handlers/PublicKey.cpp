
#include <ntddk.h>
#include "..\..\..\..\..\JimSec\JimSec\Include\IOCTL\Handlers\PublicKey.h"

IOCTL_Handlers::PublicKey::PublicKey(RSA::MemoryKey* memoryKey)
{
	_MemoryKey = memoryKey;
}

NTSTATUS IOCTL_Handlers::PublicKey::Load(PIRP Irp, PIO_STACK_LOCATION stack)
{
	PUCHAR input = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	return _MemoryKey->LoadPublicKey(input, inputSize);
}