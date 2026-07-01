#pragma once

namespace Process
{
    class ProcessHelper
    {
    public:
        static PKPROCESS GetByPid(HANDLE pid);
    };
}

