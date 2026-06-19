#include "..\..\..\..\JimSec\JimSec\SecurityDriver.h"
#include "..\..\..\..\JimSec\JimSec\Include\RSA\MemoryKey.h"

RSA::MemoryKey::~MemoryKey()
{
	this->FreePublicKeyStorage();
}

NTSTATUS RSA::MemoryKey::Init()
{
	gPublicKey.Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_KEY_SIZE, 'JSec');
	if (!gPublicKey.Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;
	gPublicKey.Size = 0;
	return STATUS_SUCCESS;
}

NTSTATUS RSA::MemoryKey::LoadPublicKey(PUCHAR input, ULONG size)
{
	if (!input || size == 0)
		return STATUS_INVALID_PARAMETER;
	if (size > MAX_KEY_SIZE)
		return STATUS_BUFFER_TOO_SMALL;
	if (!gPublicKey.Buffer)
		return STATUS_DEVICE_NOT_READY;
	RtlCopyMemory(gPublicKey.Buffer, input, size);
	gPublicKey.Size = size;
	return STATUS_SUCCESS;
}

VOID RSA::MemoryKey::FreePublicKeyStorage()
{
	if (gPublicKey.Buffer)
	{
		ExFreePoolWithTag(gPublicKey.Buffer, 'JSec');
		gPublicKey.Buffer = NULL;
		gPublicKey.Size = 0;
	}
}
