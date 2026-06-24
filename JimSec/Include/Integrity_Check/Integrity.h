#pragma once
#include <ntddk.h>
#include "../../../JimSec/Include/Integrity_Check/Common/SHA_256.h"
#include "../../../JimSec/Include/Integrity_Check/Common/Macros.h"
#include "../../../JimSec/Include/Integrity_Check/Types/SHA256_CTX.h"

namespace Integrity_Check
{
	class Integrity
	{
	private:
		Common::SHA_256 _sha256;
	public:
		BOOLEAN Check(
			ULONG pid,          // Optioneel te gebruiken voor proces-context switching
			PVOID base,         // Startadres van het te controleren geheugen
			SIZE_T size,        // Grootte van het geheugenblok
			BOOLEAN* modified
		);
	};
}