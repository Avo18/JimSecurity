#pragma once

#include <sal.h>
#include "../../../../JimSec/SharedLib/Include/ECDH_256/Types/Context.h"

#define ECDH_PUBLIC_KEY_MAX_SIZE 256

namespace ECDH_256
{
	class ECDH
	{
	public:
		ECDH();
		~ECDH();
		NTSTATUS Initialize(_Out_ P_CONTEXT context);
		NTSTATUS GetPublicKey(P_CONTEXT context, _Out_writes_bytes_to_(ECDH_PUBLIC_KEY_MAX_SIZE, *publicKeySize) unsigned char* publicKey, _Inout_ size_t* publicKeySize);
		void Cleanup(_Inout_ P_CONTEXT context);
	};
}