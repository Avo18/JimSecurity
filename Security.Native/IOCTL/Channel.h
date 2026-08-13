#pragma once

namespace IOCTL
{
	class Packet;
	class Channel
	{
	private:
		HANDLE _handleDevice;
		DWORD* _sessionKey;
	public:
		Channel(_In_ HANDLE handleDevice, _In_ DWORD* sessionKey);
		~Channel();
		DWORD Send(_Inout_ Packet* packet);
	};
}