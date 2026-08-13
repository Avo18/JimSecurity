#include "../../../../JimSec/SharedLib/Include/ECDH_256/ECDH.h"
#include "../../../../Program Files (x86)/Windows Kits/10/Include/10.0.28000.0/km/wdm.h"

namespace ECDH_256
{
	ECDH::ECDH()
	{
	}
	ECDH::~ECDH()
	{
	}
	NTSTATUS ECDH::Initialize(P_CONTEXT context)
	{
		if (!context)
			return STATUS_INVALID_PARAMETER;
		RtlZeroMemory(context, sizeof(CONTEXT));
		NTSTATUS status = BCryptOpenAlgorithmProvider(&context->Algorithm, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
		if (!BCRYPT_SUCCESS(status))
			return status;
		status = BCryptGenerateKeyPair(context->Algorithm, &context->PrivateKey, 256, 0);
		if (!BCRYPT_SUCCESS(status))
			return status;
		status = BCryptFinalizeKeyPair(context->PrivateKey, 0);
		if (!BCRYPT_SUCCESS(status))
			return status;
		return STATUS_SUCCESS;
    }

	NTSTATUS ECDH::GetPublicKey(P_CONTEXT context, unsigned char* publicKey, size_t* publicKeySize)
	{
		if (!context || !publicKey || !publicKeySize)
			return STATUS_INVALID_PARAMETER;
		ULONG resultSize = 0;
		NTSTATUS status = BCryptExportKey(context->PrivateKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, publicKey, (ULONG)*publicKeySize, &resultSize, 0);
		if (!BCRYPT_SUCCESS(status))
			return status;
		*publicKeySize = resultSize;
		return STATUS_SUCCESS;
	}

	void ECDH::Cleanup(P_CONTEXT context)
	{
		if (context)
		{
			if (context->PrivateKey)
			{
				BCryptDestroyKey(context->PrivateKey);
				context->PrivateKey = nullptr;
			}
			if (context->Algorithm)
			{
				BCryptCloseAlgorithmProvider(context->Algorithm, 0);
				context->Algorithm = nullptr;
			}
			RtlZeroMemory(context, sizeof(CONTEXT));
		}
	}
}