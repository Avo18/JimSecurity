#include "..\..\SecurityDriver.h"
#include "..\Sessions\Auth.h"
//#include <xkeycheck.h>

// inladen van publieke key van RSA
#define MAX_KEY_SIZE 512  // veilig voor RSA-4096 blob ruimte (ruim genomen)

typedef struct _PUBLIC_KEY
{
    PUCHAR Buffer;     // pointer naar allocated kernel memory
    ULONG Size;        // huidige grootte
    ULONG Hash;       // optional integrity check
} _PUBLIC_KEY;

_PUBLIC_KEY gPublicKey = { 0 };

namespace RSA
{
    class MemoryKey
    {
    public:
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
