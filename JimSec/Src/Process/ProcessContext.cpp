#pragma once
#include <ntifs.h>
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Kernel/Windows/NtProcess.h"

using namespace Process;
namespace Process
{
    Context::Context(PKPROCESS process)
    {
        m_process = process;
        m_attached = false;
    }

    PKPROCESS Context::GetProcess() const
    {
        return m_process;
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

    Context::~Context()
    {
        if (m_attached)
            KeUnstackDetachProcess(&m_state);
    }
}