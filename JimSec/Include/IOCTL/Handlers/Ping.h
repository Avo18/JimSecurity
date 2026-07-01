#pragma once

namespace IOCTL_Handlers
{
	class Ping
	{
	public:
		NTSTATUS Send();
	};
}