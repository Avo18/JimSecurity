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
        NTSTATUS Read(PKPROCESS process, PVOID address, PVOID* buffer, SIZE_T size, SIZE_T bytesRead);
    };
}
