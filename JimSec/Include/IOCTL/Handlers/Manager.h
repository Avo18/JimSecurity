#pragma once
#include "../../../../JimSec/Include/AntiCheat/Manager.h"

namespace IOCTL_Handlers
{
	class AntiCheat::Manager;
	class Manager
	{
	private:
		AntiCheat::Manager* _manager;
	public:
		Manager(AntiCheat::Manager* manager);
		NTSTATUS Start(PIRP irp, PIO_STACK_LOCATION stack);
		NTSTATUS Scan();
	};
}