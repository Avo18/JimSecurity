//--------------------------
//   Process internals
//
//  vb: PEB (Processs Enrionment Blocks) / Process Info
//--------------------------

#pragma once
#include <ntddk.h>

extern "C" PVOID PsGetProcessPeb(PKPROCESS Process);