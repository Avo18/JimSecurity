#include "..\SecurityDriver.h"
#include "..\Sessions\Auth.h"
#include <xkeycheck.h>


BOOLEAN VerifySignature(BYTE* signature)
{
	BCRYPT_KEY_HANDLE PublicKey = NULL;
	return BCryptVerifySignature(
		PublicKey,
		NULL,
		gSession.Challenge,
		sizeof(gSession.Challenge),
		signature,
		sizeof(signature),
		BCRYPT_PAD_PKCS1
	);
}
