#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Game.h"

namespace AntiCheat
{
	class Manager
	{
	private:
		Process::Game* _game;
		BOOLEAN StartGame(HANDLE pid);
	public:
		Manager(HANDLE pid);
		~Manager();
		void StopGame();
		NTSTATUS PerformScan();
	};
}