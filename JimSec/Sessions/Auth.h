#pragma once
#include "..\SecurityDriver.h"

typedef struct
{
    BOOLEAN Authenticated;
    HANDLE ProcessId;
    unsigned char Challenge[32];
} DRIVER_SESSION;

DRIVER_SESSION gSession = {};