#pragma once

//#include <ntddk.h>
//#include <wdf.h>

// kijkt of HVCI aan staat.
// hvci is een hypervisor die bepaalde beveiligingsfuncties biedt, zoals het isoleren van kritieke systeemprocessen en het voorkomen van bepaalde soorten aanvallen.
// Windows Security -> Device Security -> Core Isolation -> Memory Integrity aan (herstart pc)
#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x02

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

//typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
//    ULONG Length;
//    ULONG CodeIntegrityOptions;
//} SYSTEM_CODEINTEGRITY_INFORMATION;