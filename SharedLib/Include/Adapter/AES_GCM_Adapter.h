#pragma once
#include "../Packet.h"
#include "../AES-GCM.h"

using namespace Shared;
namespace Adapter
{
	template<typename T> class AES_GCM_Adapter
	{
	private:
		AES_GCM* _aesGcm;
	public:
		AES_GCM_Adapter() {}
		AES_GCM_Adapter(unsigned char* key)
			: _aesGcm(new AES_GCM(key))
		{
		}
		bool Encrypt(T* obj)
		{
			return _easGcm.Encrypt(obj);
		}
		bool Decrypt(T* obj)
		{
			return _aesGcm.Decrypt(obj);
		}
		~AES_GCM_Adapter()
		{
			_aesGcm = nullptr;
		}
	};
}
