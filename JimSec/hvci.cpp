
#include "HVCI.h"


//BOOLEAN IsHvciEnabled()
//{
    //SYSTEM_CODEINTEGRITY_INFORMATION info;
    //RtlZeroMemory(&info, sizeof(info));

    //info.Length = sizeof(info);

    //NTSTATUS status =
    //    ZwQuerySystemInformation(
    //        SystemCodeIntegrityInformation,
    //        &info,
    //        sizeof(info),
    //        NULL
    //    );

    //if (!NT_SUCCESS(status))
    //    return FALSE;

    //if (info.CodeIntegrityOptions &
    //    CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED)
    //{
    //    return TRUE;
    //}

//    return FALSE;
//}