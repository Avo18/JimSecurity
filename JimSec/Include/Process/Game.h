#pragma once
#include "Module.h"
#include "ProcessContext.h"

namespace Process
{
	class Game
	{
	public:
		bool Initialize(PEPROCESS process);
		void Shutdown();

	private:
		Context* m_context;
		Module* m_module;
        BOOLEAN m_initialized;
	};
}