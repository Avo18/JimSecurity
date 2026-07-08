#pragma once
#include "..\..\..\..\JimSec\JimSec\SecurityDriver.h"
#include "..\..\..\..\JimSec\JimSec\Include\RSA\MemoryKey.h"

extern IOCTL_Types::PUBLIC_KEY gPublicKey = {};

namespace RSA
{
	MemoryKey::MemoryKey()
	{
		gPublicKey.Buffer = NULL;
		gPublicKey.Size = 0;
		gPublicKey.Hash = 0;
	}

	MemoryKey::~MemoryKey()
	{
		this->FreePublicKeyStorage();
	}

	NTSTATUS MemoryKey::Init()
	{
		gPublicKey.Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_KEY_SIZE, 'JSec');
		if (!gPublicKey.Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		gPublicKey.Size = 0;
		return STATUS_SUCCESS;
	}

	NTSTATUS MemoryKey::LoadPublicKey(PUCHAR input, ULONG size)
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

	VOID MemoryKey::FreePublicKeyStorage()
	{
		if (gPublicKey.Buffer)
		{
			ExFreePoolWithTag(gPublicKey.Buffer, 'JSec');
			gPublicKey.Buffer = NULL;
			gPublicKey.Size = 0;
		}
	}
}