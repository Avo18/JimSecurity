#pragma once
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"

namespace Process
{
    Context::Context(PEPROCESS process)
    {
        m_process = process;
        m_attached = false;
    }

    PEPROCESS& Context::GetProcess()
    {
        return m_process;
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