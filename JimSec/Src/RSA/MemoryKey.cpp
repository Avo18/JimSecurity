#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "..\..\..\..\JimSec\JimSec\Include\RSA\MemoryKey.h"

extern IOCTL_Types::PUBLIC_KEY _publicKey = {};

namespace RSA
{
	MemoryKey::MemoryKey()
	{
		_publicKey.Buffer = NULL;
		_publicKey.Size = 0;
		_publicKey.Hash = 0;
	}

	MemoryKey::~MemoryKey()
	{
		this->FreePublicKeyStorage();
	}

	NTSTATUS MemoryKey::Init()
	{
		_publicKey.Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_KEY_SIZE, 'JSec');
		if (!_publicKey.Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		_publicKey.Size = 0;
		return STATUS_SUCCESS;
	}

	NTSTATUS MemoryKey::LoadPublicKey(PUCHAR input, ULONG size)
	{
		if (!input || size == 0)
			return STATUS_INVALID_PARAMETER;
		if (size > MAX_KEY_SIZE)
			return STATUS_BUFFER_TOO_SMALL;
		if (!_publicKey.Buffer)
			return STATUS_DEVICE_NOT_READY;
		RtlCopyMemory(_publicKey.Buffer, input, size);
		_publicKey.Size = size;
		return STATUS_SUCCESS;
	}

	VOID MemoryKey::FreePublicKeyStorage()
	{
		if (_publicKey.Buffer)
		{
			ExFreePoolWithTag(_publicKey.Buffer, 'JSec');
			_publicKey.Buffer = NULL;
			_publicKey.Size = 0;
		}
	}
}