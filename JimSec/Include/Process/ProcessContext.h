//--------------------------------
//  RAII SAFE
//--------------------------------
#pragma once
#include <ntifs.h>

namespace Process
{
    class Context
    {
    public:
        explicit Context(PEPROCESS process);
        ~Context();
        PEPROCESS& GetProcess();
        void Attach();
        void Detach();

    private:
        PEPROCESS m_process;
        KAPC_STATE m_state;
        BOOLEAN m_attached;
    };
}