//--------------------------------
//  RAII SAFE (Resource Acquisition Is Initialization) 
//  resources worden automatisch beheerd door object lifetime (constructor = acquire, destructor = release)
//--------------------------------
#pragma once

namespace Process
{
    class Context
    {
    private:
        PKPROCESS m_process;
        KAPC_STATE m_state;
        BOOLEAN m_attached;
    public:
        explicit Context(PKPROCESS process);
        ~Context();
        PKPROCESS GetProcess() const;
        PVOID GetImageBase() const;
        void Attach();
        void Detach();
    };
}