#pragma once
#include <bcrypt.h>

namespace ECDH_256
{
	typedef struct CONTEXT
	{
		BCRYPT_ALG_HANDLE    Algorithm;
		BCRYPT_KEY_HANDLE    PrivateKey;
	} CONTEXT, * P_CONTEXT;
}