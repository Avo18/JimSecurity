//-----------------------------------
//  Memory operaties
//
// VB: Copy/Reads/Writes in geheugen
//-----------------------------------

#pragma once
#include <ntifs.h>
#include <ntimage.h>

extern "C" 
NTSTATUS MmCopyVirtualMemory(
	PKPROCESS SourceProcess, PVOID SourceAddress, PKPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
