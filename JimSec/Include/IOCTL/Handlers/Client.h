#pragma once

namespace IOCTL_Handlers
{
	class Client
	{
	public:
		NTSTATUS Validate(PIRP irp, PIO_STACK_LOCATION stack);
	};
}