#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Game.h"

namespace Process
{
    Game::Game()
        : m_context(nullptr), m_module(nullptr), m_initialized(false)
    {
    }

    bool Game::Initialize(PEPROCESS process)
    {
        if (!process)
            return false;

        m_context = &Context(process);
        m_context->Attach();

        PVOID base = nullptr; // je krijgt dit via PsGetProcessSectionBaseAddress etc.

        m_module = &Module(base);

        m_initialized = true;
        return true;
    }

    void Game::Shutdown()
    {
        if (!m_initialized)
            return;

        if (m_module)
        {
            delete m_module;
            m_module = nullptr;
        }

        if (m_context)
        {
            m_context->Detach();
            delete m_context;
            m_context = nullptr;
        }

        m_initialized = false;
    }

    Game::~Game()
    {
        Shutdown();
    }
}