#pragma once

namespace Process
{
    class Context;
    class Memory;
    class ModuleAnalyzer;
    class Module;
    class Game
    {
    public:
        Game();
        Game(Context* context);
        Game(PKPROCESS process, PVOID moduleBase);
        ~Game();

        bool Initialize(PKPROCESS process, PVOID moduleBase);
        void Shutdown();
        NTSTATUS RunChecks();

        Context* GetContext();
        Memory* GetMemory();
        Module* GetModule();
        ModuleAnalyzer* GetAnalyzer();
    
    private:
        Context* _context;
        Memory* _memory;
        Module* _module;
        ModuleAnalyzer* _analyzer;
        BOOLEAN _initialized;
    };
}