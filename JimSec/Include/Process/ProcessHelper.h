#pragma once

namespace Process
{
    class ProcessHelper
    {
    public:
        static PKPROCESS GetByPid(_In_ HANDLE pid);
    };
}

