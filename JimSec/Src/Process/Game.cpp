#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Game.h"
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../JimSec/JimSec/Include/Process/ModuleAnalyzer.h"
#include "../../../../JimSec/JimSec/Include/Process/Module.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Utils/Kernel.h"

namespace Process
{
    Game::Game()
        : _context(nullptr), _module(nullptr), _initialized(false)
    {
    }
    Game::Game(Context* context)
        : _context(context), _module(nullptr), _initialized(false)
    {
        Initialize(_context->GetProcess(), _context->GetImageBase());
    }

    Game::Game(PKPROCESS process, PVOID moduleBase)
    {
        Initialize(process, moduleBase);
    }

    bool Game::Initialize(PKPROCESS process, PVOID moduleBase)
    {
        if (!process)
            return false;

        // je krijgt moduleBase via PsGetProcessSectionBaseAddress etc.
        _module = &Module(moduleBase);
        _context = &Context(process);
        _memory = &Memory(*_context);
        _analyzer = &ModuleAnalyzer(*_memory);

        _context->Attach();
        _initialized = true;
        return true;
    }

    Memory* Game::GetMemory()
    {
        return _memory;
    }
    ModuleAnalyzer* Game::GetAnalyzer()
    {
        return _analyzer;
    }
    Context* Game::GetContext()
    {
        return _context;
    }
    Module* Game::GetModule()
    {
        return _module;
    }
    NTSTATUS Game::RunChecks()
    {
        NTSTATUS status;

        PIMAGE_NT_HEADERS nt = _module->GetNtHeaders();

        status = _analyzer->ScanJumps(
			_module->GetSectionHeaders(nt),
			_module->GetSectionIndex(nt, _module->GetSectionHeaders(nt), Enum::Section::MachineCode),
			_context->GetImageBase()
		);

        if (!NT_SUCCESS(status))
            return status;

		status = _analyzer->IsAddressInLegitimateModule(_context->GetProcess(), (ULONG64)_context->GetImageBase());

        if (!NT_SUCCESS(status))
            return status;

        return STATUS_SUCCESS;
    }

    void Game::Shutdown()
    {
        if (!_initialized)
            return;

        if (_module)
        {
            delete(_module);
            _module = nullptr;
        }

        if (_context)
        {
            _context->Detach();
            delete(_context);
            _context = nullptr;
        }

        _initialized = false;
    }

    Game::~Game()
    {
        Shutdown();
    }
}