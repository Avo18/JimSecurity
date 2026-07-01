#include <ntddk.h>
#include <wdf.h>
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Auth.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/PublicKey.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/Handlers/Func/IoctlHandlerFunc.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "../../../JimSec/Include/IOCTL/Handlers/Ping.h"
#include "../../IOCTL.h"

IOCTL::IoControlList::IoControlList()
{
	this->publicKey = &IOCTL_Handlers::PublicKey(&RSA::MemoryKey());
    IOCTL_Handlers::Ping* ping = &IOCTL_Handlers::Ping();

	g_Table[0] = { IOCTL_LOAD_KEY, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke3<&IOCTL_Handlers::PublicKey::Load>, &publicKey};
    g_Table[1] = { IOCTL_PING, IoctlHandlerFunc<IOCTL_Handlers::Ping>::Invoke0<&Ping::Send>, &ping};
//    g_Table[2] = { IOCTL_LOAD_KEY, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke(&publicKey, &IOCTL_Handlers::PublicKey::Load) , &publicKey};
}

IOCTL_ENTRY* IOCTL::IoControlList::FindHandler(ULONG ioctl)
{
    for (int i = 0; i < ARRAYSIZE(g_Table); i++)
    {
        if (g_Table[i].Ioctl == ioctl)
            return &g_Table[i]; // Geef een pointer naar de hele entry terug
    }
    return NULL;
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
