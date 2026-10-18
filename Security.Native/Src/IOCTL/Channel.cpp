//#include "../pch.h"

#include <Windows.h>
#include <winioctl.h>
#include "../../../Security.Native/IOCTL/Channel.h"
#include <Packet.h>
#include <AES-GCM.h>
#include <Adapter/AES_GCM_Adapter.h>
#include <Adapter/AES_GCM/PacketAdapter.h>

using namespace Shared;
using namespace Adapter;

namespace IOCTL
{
	Channel::Channel(HANDLE handleDevice, unsigned char* sessionKey)
	{
		_handleDevice = handleDevice;
		_sessionKey = sessionKey;
	}
	Channel::~Channel()
	{
		_handleDevice = nullptr;
		_sessionKey = nullptr;
	}
	DWORD Channel::Send(Shared::Packet* packet)
	{
		DWORD returned;
		PacketAdapter adapter(this->_sessionKey);
		if (adapter.Encrypt(packet))
		{
			if (DeviceIoControl(_handleDevice, packet->GetCommand(), &packet, sizeof(packet), nullptr, 0, &returned, nullptr))
			{
				return returned;
			}
			else
			{
				return GetLastError();
			}
		}
		return returned;
	}

	DWORD Channel::Receive(Shared::Packet* packet)
	{
		DWORD returned;
		PacketAdapter adapter(this->_sessionKey);
		if (DeviceIoControl(_handleDevice, packet->GetCommand(), nullptr, 0, &packet, sizeof(packet), &returned, nullptr))
		{
			if (adapter.Decrypt(packet))
			{
				return returned;
			}
			else
			{
				return returned;
			}
		}
		else
		{
			return GetLastError();
		}
	}
}