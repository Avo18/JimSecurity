#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Module.h"
namespace Process
{
    class Context;
    class Memory;
    class ModuleAnalyzer;
    class Module;
    class Game
    {
    public:
        //Game();
        Game(Process::Context* context);
        Game(PKPROCESS process, PVOID moduleBase);
        ~Game();

        bool Initialize(_In_ PKPROCESS process, _In_ PVOID moduleBase);
        void Shutdown();
        NTSTATUS RunChecks();

        Process::Context* GetContext();
        Process::Memory* GetMemory();
        Process::Module* GetModule();
        Process::ModuleAnalyzer* GetAnalyzer();
    
    private:
        Process::Context* _context;
        Process::Memory* _memory;
        Process::Module* _module;
        Process::ModuleAnalyzer* _analyzer;
        BOOLEAN _initialized;
    };
}