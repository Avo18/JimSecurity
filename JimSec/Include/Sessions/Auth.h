#pragma once
#include "..\..\SecurityDriver.h"

typedef struct
{
    BOOLEAN Authenticated;
    HANDLE ProcessId;
    unsigned char Challenge[32];
} DRIVER_SESSION;

extern DRIVER_SESSION gSession;