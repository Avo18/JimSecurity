#include <ntddk.h>
#include "../../../../JimSec/Include/IOCTL/Handlers/Ping.h"

namespace IOCTL_Handlers
{
	NTSTATUS Ping::Send()
	{
		return STATUS_SUCCESS;
	}
}