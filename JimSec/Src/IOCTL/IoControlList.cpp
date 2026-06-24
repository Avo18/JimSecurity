#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "../../IOCTL.h"

IOCTL::IoControlList::IoControlList()
{
	this->publicKey = &IOCTL_Handlers::PublicKey(&RSA::MemoryKey());
	g_Table[0] = { IOCTL_AUTH, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke<&IOCTL_Handlers::PublicKey::Load>, &publicKey };
}

PIOCTL_HANDLER IOCTL::IoControlList::FindHandler(ULONG ioctl)
{
	for (int i = 0; i < ARRAYSIZE(g_Table); i++)
	{
		if (g_Table[i].Ioctl == ioctl)
			return g_Table[i].Handler;
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
