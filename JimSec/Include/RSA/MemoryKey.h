#pragma once
#include "..\..\SecurityDriver.h"
#include "..\Sessions\Auth.h"
#include "../../../JimSec/Include/IOCTL/Types/PublicKey.h"
//#include <xkeycheck.h>

// inladen van publieke key van RSA
#define MAX_KEY_SIZE 512  // veilig voor RSA-4096 blob ruimte (ruim genomen)

namespace RSA
{
    class MemoryKey
    {
    public:
        MemoryKey();
        ~MemoryKey();
        NTSTATUS Init();
        NTSTATUS LoadPublicKey(PUCHAR input, ULONG size);
        VOID FreePublicKeyStorage();
    };
};




// dit is voor Security.Native library
//BOOLEAN VerifySignature(BYTE* signature)
//{
//	BCRYPT_KEY_HANDLE PublicKey = NULL;
//	return BCryptVerifySignature(
//		PublicKey,
//		NULL,
//		gSession.Challenge,
//		sizeof(gSession.Challenge),
//		signature,
//		sizeof(signature),
//		BCRYPT_PAD_PKCS1
//	);
//}
