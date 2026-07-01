#pragma once

namespace AntiCheat
{
	class Manager
	{
	private:
		Game* _game;
	public:
		BOOLEAN StartGame(HANDLE pid);
		void StopGame();
		NTSTATUS PerformScan();
	};
}