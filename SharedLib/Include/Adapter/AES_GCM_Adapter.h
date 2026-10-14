#pragma once
#include "../Packet.h"
#include "../AES-GCM.h"
#include <sal.h>
#include <ntdef.h>

using namespace Shared;
namespace Adapter
{
	template<typename T> class AES_GCM_Adapter
	{
	private:
		AES_GCM<T>* _aesGcm;
	protected:
		AES_GCM_Adapter() {}
		AES_GCM_Adapter(unsigned char* key)
			: _aesGcm(new AES_GCM<T>(key))
		{
		}
		bool Encrypt(_In_ PUCHAR tag, _In_ PUCHAR nonce, _Inout_ PUCHAR* buffer, _Inout_ PULONG* size)
		{
			return _easGcm.Encrypt(tag, nonce, buffer, size);
		}
		bool Decrypt(_In_ PUCHAR tag, _In_ PUCHAR nonce, _Inout_ PUCHAR* buffer, _Inout_ PULONG* size)
		{
			return _aesGcm.Decrypt(tag, nonce, buffer, size);
		}
		~AES_GCM_Adapter()
		{
			_aesGcm = nullptr;
		}
	};
}
