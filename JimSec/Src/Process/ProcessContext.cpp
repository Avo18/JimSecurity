#include <ntifs.h>
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Kernel/Windows/NtProcess.h"

namespace Process
{
    Context::Context(PKPROCESS process)
    {
        m_state = {};
        m_process = process;
        m_attached = false;
    }
    Context::~Context()
    {
        if (m_attached)
            KeUnstackDetachProcess(&m_state);
    }

    PKPROCESS Context::GetProcess() const
    {
        return (struct _KPROCESS*)m_process;
    }
    PVOID Context::GetImageBase() const
    {
        return PsGetProcessSectionBaseAddress(m_process);
    }

    void Context::Attach()
    {
        if (!m_process || m_attached)
            return;

        KeStackAttachProcess(m_process, &m_state);
        m_attached = true;
    }

    void Context::Detach()
    {
        if (!m_attached)
            return;

        KeUnstackDetachProcess(&m_state);
        m_attached = false;
    }
}