#pragma once
#include <Packet.h>
#include <Windows.h>
#include <ntstatus.h>

using namespace Shared;

namespace Packets
{
	class PingPacket
	{
	public:
		Packet* Ping(__int8* authenticationTag)
		{
			Packet* packet = new Packet(0xC00800);
			packet->Add<DWORD>(0x20);
			packet->AddAuthenticationTag(authenticationTag);
			return packet;
		}
	};
}
