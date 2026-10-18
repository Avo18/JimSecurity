#include <ntifs.h>
#include "../../../JimSec/Include/Process/ProcessHelper.h"

namespace Process
{
    PKPROCESS ProcessHelper::GetByPid(HANDLE pid) {
        PKPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
            return process;
        }
        return NULL;
    }
}