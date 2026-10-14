#pragma once

namespace IOCTL
{
	class Shared::Packet;
	class Channel
	{
	private:
		HANDLE _handleDevice;
		unsigned char* _sessionKey;
	public:
		Channel(_In_ HANDLE handleDevice, _In_ unsigned char* sessionKey);
		~Channel();
		DWORD Send(_Inout_ Shared::Packet* packet);
		DWORD Receive(_Inout_ Shared::Packet* packet);
	};
}