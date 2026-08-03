#include <ntifs.h>
#include "../../../../JimSec/Include/IOCTL/Handlers/Manager.h"

namespace IOCTL_Handlers
{
	Manager::Manager(AntiCheat::Manager* manager) 
		: _manager(manager) 
	{
	};

	NTSTATUS Manager::Start(PIRP irp, PIO_STACK_LOCATION stack) {
		if (irp->AssociatedIrp.SystemBuffer == nullptr ||
			stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE))
		{
			return STATUS_INVALID_PARAMETER;
		}

		HANDLE pid = *(HANDLE*)irp->AssociatedIrp.SystemBuffer;
		BOOLEAN started = this->_manager->StartGame(pid);
		if (started) {
			return STATUS_SUCCESS;
		}
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS Manager::Scan()
	{
		return this->_manager->PerformScan();
	}
}

