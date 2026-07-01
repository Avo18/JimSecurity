#pragma once

using namespace IOCTL_Handlers;

#define IOCTL_COUNT 2

namespace IOCTL
{
    class IoControlList
    {
    private:
        IOCTL_Handlers::PublicKey* publicKey;

        IOCTL_ENTRY g_Table[IOCTL_COUNT];
    public:
        IoControlList();
        IOCTL_ENTRY* FindHandler(ULONG ioctl);
    };
}






/*
auto entry = FindHandler(Ioctl);

if(entry)
{
    return entry->Handler(
        entry->Context,
        Irp,
        stack
    );
}
*/