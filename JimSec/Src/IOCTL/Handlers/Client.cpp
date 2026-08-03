#include <ntifs.h>
#include "../../../Include/IOCTL/Handlers/Client.h"
#include "../../../Include/Shared_Protocol/Protocol.h"

namespace IOCTL_Handlers
{
    typedef struct _AUTH_REQUEST {
        ULONG Magic;
        ULONG ClientId;
    } AUTH_REQUEST;

	NTSTATUS Client::Validate(PIRP irp, PIO_STACK_LOCATION stack)
	{
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;
        ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

            if (!buffer || size < sizeof(AUTH_REQUEST))
                return STATUS_ACCESS_DENIED;

            AUTH_REQUEST* req = (AUTH_REQUEST*)buffer;

            if (req->Magic != IOCTL_VALIDATE_CLIENT)
                return STATUS_ACCESS_DENIED;

            return STATUS_SUCCESS;
	}
}