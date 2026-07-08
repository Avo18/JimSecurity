#include <ntddk.h>
#include "..\..\..\..\..\JimSec\JimSec\Include\IOCTL\Handlers\PublicKey.h"

using namespace RSA;
namespace IOCTL_Handlers
{
	PublicKey::PublicKey(RSA::MemoryKey* memoryKey)
		: _memoryKey(memoryKey)
	{
	};

	NTSTATUS PublicKey::Load(PIRP Irp, PIO_STACK_LOCATION stack)
	{
		PUCHAR input = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
		ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
		return _memoryKey->LoadPublicKey(input, inputSize);
	};
}