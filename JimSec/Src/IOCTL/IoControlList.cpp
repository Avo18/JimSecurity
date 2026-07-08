#include <ntddk.h>
#include <wdf.h>
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Auth.h"
#include "../../../../JimSec/JimSec/Include/RSA/MemoryKey.h"
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "../../../JimSec/Include/IOCTL/Handlers/Ping.h"
#include "../../IOCTL.h"

namespace IOCTL
{
    IoControlList::IoControlList()
    {
        RSA::MemoryKey* memoryKey = &RSA::MemoryKey();
        this->publicKey = &IOCTL_Handlers::PublicKey(memoryKey);
        IOCTL_Handlers::Ping* ping = &IOCTL_Handlers::Ping();

        _Table[0] = { IOCTL_LOAD_KEY, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke3<&IOCTL_Handlers::PublicKey::Load>, &publicKey };
        _Table[1] = { IOCTL_PING, IoctlHandlerFunc<IOCTL_Handlers::Ping>::Invoke0<&IOCTL_Handlers::Ping::Send>, &ping};
    //    g_Table[2] = { IOCTL_LOAD_KEY, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke(&publicKey, &IOCTL_Handlers::PublicKey::Load) , &publicKey};
    }

    IOCTL_ENTRY* IoControlList::FindHandler(ULONG ioctl)
    {
        for (int i = 0; i < ARRAYSIZE(_Table); i++)
        {
            if (_Table[i].Ioctl == ioctl)
                return &_Table[i];
        }
        return NULL;
    }
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
