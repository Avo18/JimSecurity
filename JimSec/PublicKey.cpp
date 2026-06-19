
#include <ntddk.h>
//#include "..\..\JimSec\JimSec\Include\IOCTL\Types\PublicKey.h"
#include "..\..\JimSec\JimSec\Include\RSA\MemoryKey.h"

using namespace RSA;


class PublicKey
{
private:
	MemoryKey* _MemoryKey;
public:
	PublicKey(MemoryKey* memoryKey) : 
        _MemoryKey(memoryKey) {
    }
    NTSTATUS Load(PIRP Irp, PIO_STACK_LOCATION stack)
    {
        PUCHAR input = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;

        return _MemoryKey->LoadPublicKey(input, inputSize);
    }
};