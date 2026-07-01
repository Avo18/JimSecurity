//--------------------------
//   Process internals
//
//  vb: PEB (Processs Enrionment Blocks) / Process Info
//--------------------------

#pragma once
#include <ntifs.h>
#include <ntimage.h>

extern "C" PVOID PsGetProcessPeb(PKPROCESS Process);
extern "C" PVOID PsGetProcessSectionBaseAddress(PKPROCESS Process);