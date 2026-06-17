#include "SecurityDriver.h"
//#include <wincrypt.h>

// inladen van publieke key van RSA
#define MAX_KEY_SIZE 512  // veilig voor RSA-4096 blob ruimte (ruim genomen)

typedef struct _PUBLIC_KEY
{
    PUCHAR Buffer;     // pointer naar allocated kernel memory
    ULONG Size;        // huidige grootte
    ULONG Hash;       // optional integrity check
} _PUBLIC_KEY;

_PUBLIC_KEY gPublicKey = { 0 };

NTSTATUS Init()
{
    gPublicKey.Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_KEY_SIZE, 'JSec');

    if (!gPublicKey.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    gPublicKey.Size = 0;

    return STATUS_SUCCESS;
}

//NTSTATUS LoadPublicKey(PUCHAR keyBlob, ULONG keyBlobSize)
//{
//    if (!gAlgHandle)
//        return STATUS_INVALID_HANDLE;
//
//    NTSTATUS status = BCryptImportKeyPair(gAlgHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, &gPublicKey, keyBlob, keyBlobSize, 0);
//
//    return status;
//}
NTSTATUS LoadPublicKey(PUCHAR input, ULONG size)
{
    if (!input || size == 0)
        return STATUS_INVALID_PARAMETER;

    if (size > MAX_KEY_SIZE)
        return STATUS_BUFFER_TOO_SMALL;

    if (!gPublicKey.Buffer)
        return STATUS_DEVICE_NOT_READY;

    RtlCopyMemory(gPublicKey.Buffer, input, size);
    gPublicKey.Size = size;

    return STATUS_SUCCESS;
}

VOID FreePublicKeyStorage()
{
    if (gPublicKey.Buffer)
    {
        ExFreePoolWithTag(gPublicKey.Buffer, 'JSec');
        gPublicKey.Buffer = NULL;
        gPublicKey.Size = 0;
    }
}
