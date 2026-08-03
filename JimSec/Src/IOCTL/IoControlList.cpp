#include <ntddk.h>
#include <wdm.h>
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Auth.h"
#include "../../../../JimSec/JimSec/Include/Shared_Protocol/Protocol.h"
#include "../../../../JimSec/JimSec/Include/RSA/MemoryKey.h"
#include "../../../../JimSec/JimSec/Include/Process/Memory.h"
#include "../../../../JimSec/JimSec/Include/IOCTL/IoControlList.h"
#include "../../../JimSec/Include/IOCTL/Handlers/Ping.h"
#include "../../../JimSec/Include/IOCTL/Handlers/Manager.h"
#include "../../../JimSec/Include/IOCTL/Handlers/Client.h"
#include "../../../JimSec/Include/AntiCheat/Manager.h"
#include "../../IOCTL.h"

namespace IOCTL
{
    IoControlList::IoControlList()
    {
        RSA::MemoryKey* memoryKey = &RSA::MemoryKey();
        this->publicKey = &IOCTL_Handlers::PublicKey(memoryKey);
        IOCTL_Handlers::Ping* ping = &IOCTL_Handlers::Ping();
		IOCTL_Handlers::Manager* manager = &IOCTL_Handlers::Manager(&AntiCheat::Manager());
		IOCTL_Handlers::Client* client = &IOCTL_Handlers::Client();

        _Table[0] = { IOCTL_LOAD_KEY, IoctlHandlerFunc<IOCTL_Handlers::PublicKey>::Invoke3<&IOCTL_Handlers::PublicKey::Load>, &publicKey };
        _Table[1] = { IOCTL_PING, IoctlHandlerFunc<IOCTL_Handlers::Ping>::Invoke0<&IOCTL_Handlers::Ping::Send>, &ping};
        _Table[2] = { IOCTL_START_INITIALIZE, IoctlHandlerFunc<IOCTL_Handlers::Manager>::Invoke3<&IOCTL_Handlers::Manager::Start> , &manager};
        _Table[3] = { IOCTL_SCAN_PROCESS, IoctlHandlerFunc<IOCTL_Handlers::Manager>::Invoke0<&IOCTL_Handlers::Manager::Scan> , &manager };
        _Table[4] = { IOCTL_VALIDATE_CLIENT, IoctlHandlerFunc<IOCTL_Handlers::Client>::Invoke3<&IOCTL_Handlers::Client::Validate> , &client };
    
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

