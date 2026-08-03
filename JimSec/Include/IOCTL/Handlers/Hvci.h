#pragma once

namespace IOCTL_Handlers
{
	class Hvci
	{
	public:
		NTSTATUS IsEnabled(PIRP irp, PIO_STACK_LOCATION stack);
	};
}