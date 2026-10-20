#pragma once
#include <Packet.h>
#include <Windows.h>
#include <ntstatus.h>

using namespace Shared;

class PublicKeyPacket
{
public:
	Packet* SendPublicKeyPacket(__int8* authenticationTag, const char* publicKey, size_t publicKeySize)
	{
		Packet* packet = new Packet(0xC00801);
		packet->Add<DWORD>(static_cast<DWORD>(publicKeySize));
		packet->AddString(publicKey);
		packet->AddAuthenticationTag(authenticationTag);
		return packet;
	}
};