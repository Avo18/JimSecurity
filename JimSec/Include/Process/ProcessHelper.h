#pragma once
#include <ntifs.h>

namespace Process
{
    class ProcessHelper
    {
    public:
        static PEPROCESS GetByPid(HANDLE pid);
    };
}

