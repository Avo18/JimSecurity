#pragma once

#include "../AES_GCM_Adapter.h"
#include "../../Packet.h"

using namespace Shared;

namespace Adapter
{
	class PacketAdapter : public Adapter::AES_GCM_Adapter<Shared::Packet>
	{
	public: 
		PacketAdapter(unsigned char* key)
			: AES_GCM_Adapter(key)
		{
		}
		bool Encrypt(_Inout_ Packet* obj)
		{
			PULONG* encryptedSize = 0;
			bool resultSuccess = AES_GCM_Adapter::Encrypt(*obj->GetTag(), *obj->GetNonce(), reinterpret_cast<PUCHAR*>(*obj->GetData()), encryptedSize);
			obj->SetSize(*encryptedSize);
			return resultSuccess;
		}
		bool Decrypt(_Inout_ Packet* obj)
		{
			PULONG* decryptedSize = 0;
			bool success = AES_GCM_Adapter::Decrypt(*obj->GetTag(), *obj->GetNonce(), reinterpret_cast<PUCHAR*>(*obj->GetData()), decryptedSize);
			obj->SetSize(*decryptedSize);
			return success;
		}
	};
}
