#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"

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
