#pragma once
#include "../Packet.h"
#include "../AES-GCM.h"

using namespace Shared;
namespace Adapter
{
	template<typename T> class AES_GCM_Adapter
	{
	public:
		AES_GCM_Adapter(T* obj)
		{
			_obj = obj;
		}
		bool Encrypt(const unsigned char* key)
		{
			return _easGcm.Encrypt(_obj, key);
		}
		bool Decrypt(const unsigned char* key)
		{
			return _aesGcm.Decrypt(_obj, key);
		}
		~AES_GCM_Adapter()
		{
			_obj = nullptr;
		}
	
	private:
		T* _obj;
		AES_GCM _aesGcm;
	};
}
