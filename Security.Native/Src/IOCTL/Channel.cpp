//#include "../pch.h"

#include <Windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include "../../../JimSec/Security.Native/IOCTL/Channel.h"
#include <Packet.h>
#include <AES-GCM.h>
#include <Adapter/AES_GCM_Adapter.h>

using namespace Shared;
using namespace Adapter;

namespace IOCTL
{
	Channel::Channel(HANDLE handleDevice, DWORD* sessionKey)
	{
		_handleDevice = handleDevice;
		_sessionKey = sessionKey;
	}
	Channel::~Channel()
	{
		_handleDevice = nullptr;
	}
	DWORD Channel::Send(Packet* packet)
	{
		DWORD returned;
		AES_GCM_Adapter<Packet> adapter(nullptr);
		if (adapter.Encrypt(packet))
		{
			if (DeviceIoControl(_handleDevice, 0x800, &packet, sizeof(packet), nullptr, 0, &returned, nullptr))
			{
				return returned;
			}
			else
			{
				return GetLastError();
			}
		}
		return STATUS_UNSUCCESSFUL;
	}
}