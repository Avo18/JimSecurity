#include <ntifs.h>
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Kernel/Windows/NtProcess.h"

namespace Process
{
    Context::Context(PKPROCESS process)
    {
        _state = {};
        _process = process;
        _attached = false;
    }
    Context::~Context()
    {
        if (_attached)
            KeUnstackDetachProcess(&_state);
    }

    PKPROCESS Context::GetProcess() const
    {
        return (struct _KPROCESS*)_process;
    }
    PVOID Context::GetImageBase() const
    {
        return PsGetProcessSectionBaseAddress(_process);
    }

    void Context::Attach()
    {
        if (!_process || _attached)
            return;

        KeStackAttachProcess(_process, &_state);
        _attached = true;
    }

    void Context::Detach()
    {
        if (!_attached)
            return;

        KeUnstackDetachProcess(&_state);
        _attached = false;
    }
}