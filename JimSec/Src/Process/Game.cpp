#include "../../../../JimSec/JimSec/Include/Process/Game.h"
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../JimSec/JimSec/Include/Process/ModuleAnalyzer.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"
#include "../../../../JimSec/JimSec/Include/Utils/Kernel.h"
#include "../../../../JimSec/JimSec/Include/Process/Enum/Section.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessHelper.h"


namespace Process
{
    //Game::Game()
    //    : _context(nullptr), _module(nullptr), _initialized(false)
    //{
    //}

    Game::Game(Process::Context* context)
        : _context(context), _module(nullptr), _initialized(false)
    {
        Initialize(_context->GetProcess(), _context->GetImageBase());
    }

    Game::Game(PKPROCESS process, PVOID moduleBase)
    {
        Initialize(process, moduleBase);
    }

    Game::~Game()
    {
        Shutdown();
    }

    bool Game::Initialize(PKPROCESS process, PVOID moduleBase)
    {
        if (!process)
            return false;

        // je krijgt moduleBase via PsGetProcessSectionBaseAddress etc.
        _module = AllocateObject<Process::Module>(moduleBase);
        _context = AllocateObject<Process::Context>(process);
        _memory = AllocateObject<Process::Memory>(*_context);
        _analyzer = AllocateObject<Process::ModuleAnalyzer>(*_memory);

        _context->Attach();
        _initialized = true;
        return true;
    }

    Process::Memory* Game::GetMemory()
    {
        return _memory;
    }
    Process::ModuleAnalyzer* Game::GetAnalyzer()
    {
        return _analyzer;
    }
    Process::Context* Game::GetContext()
    {
        return _context;
    }
    Process::Module* Game::GetModule()
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
			FreeObject(_module);
            _module = nullptr;
        }

        if (_context)
        {
            _context->Detach();
            FreeObject(_context);
            _context = nullptr;
        }

        _initialized = false;
    }
}