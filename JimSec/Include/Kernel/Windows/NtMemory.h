//-----------------------------------
//  Memory operaties
//
// VB: Copy/Reads/Writes in geheugen
//-----------------------------------

#pragma once
#include <ntddk.h>

extern "C" 
NTSTATUS MmCopyVirtualMemory(
	PKPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
