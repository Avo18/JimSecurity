#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Game.h"

namespace AntiCheat
{
	class Manager
	{
	private:
		Process::Game* _game;
	public:
		Manager();
		Manager(HANDLE pid);
		~Manager();
		BOOLEAN StartGame(HANDLE pid);
		void StopGame();
		NTSTATUS PerformScan();
	};
}