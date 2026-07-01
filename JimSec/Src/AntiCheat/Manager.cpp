#pragma once
#include <ntifs.h>
#include "../../../../JimSec/JimSec/Include/AntiCheat/Manager.h"
#include "../../../../JimSec/JimSec/Include/Process/Game.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessHelper.h"
#include "../../../../JimSec/JimSec/Include/Process/ProcessContext.h"

using namespace Process;

namespace AntiCheat
{
    Manager::Manager()
    {
        _game = nullptr;
    }

    Manager::~Manager()
    {
        StopGame();
    }

    /*
	* processid met rsa decrypten en dan de game starten
    */
    BOOLEAN Manager::StartGame(HANDLE pid)
    {
        PKPROCESS process = Process::ProcessHelper::GetByPid(pid);

        if (!process)
            return false;

        Context* context = &Context(process);

        _game = new Process::Game(context);

        if (!_game)
        {
            delete(_game);
            _game = nullptr;
            
            ObDereferenceObject(process);

            return false;
        }

        /*
           Game houdt de sessie bij.
           Als je geen extra reference wilt:
           hier ObDereferenceObject gebruiken
           afhankelijk van jouw ownership model.
        */

        return true;
    }



    void Manager::StopGame()
    {
        if (_game)
        {
            _game->Shutdown();

            delete(_game);
            _game = nullptr;
        }
    }

    NTSTATUS Manager::PerformScan()
    {
        if (!_game)
            return STATUS_INVALID_DEVICE_STATE;

		_game->GetContext()->Attach();
		NTSTATUS status = _game->RunChecks();
		_game->GetContext()->Detach();

        return status;
    }
}