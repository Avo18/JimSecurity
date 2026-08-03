#pragma once

namespace Process
{
    class Context;
    class Memory
    {
    private:
        Context& _context;
    public:
        explicit Memory(Context& context);
        Context& GetContext();
        NTSTATUS Read(_In_ PKPROCESS process,_In_ PVOID address,_Inout_ PVOID* buffer, _In_ SIZE_T size, _Inout_ SIZE_T bytesRead);
    };
}
