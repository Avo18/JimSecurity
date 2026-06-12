#include <Windows.h>
#include <iostream>
#include <ntddk.h>


//DeviceIoControl(..) = WindowsAPI functie van ring3 (gebruikersmode) waarmee je een IOCTL code naar een driver kan sturen
//en eventueel data mee kan geven. De driver kan hierop reageren en data terugsturen. 
// Hiermee kunnen gebruikersmode applicaties communiceren met kernelmode drivers.

#define IOCTL_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_MAGIC 0x4A534543

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _AUTH_REQUEST {
    ULONG Magic;
    ULONG ClientId;
} AUTH_REQUEST;

class SecurityClient
{
private:
    HANDLE hDevice;

public:

    bool Connect()
    {
        hDevice = CreateFileW(
            L"\\\\.\\JimSecurity",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        return hDevice != INVALID_HANDLE_VALUE;
    }

    bool Authenticate()
    {
        AUTH_REQUEST req = {};
        req.Magic = DRIVER_MAGIC;
        req.ClientId = GetCurrentProcessId();

        DWORD returned;

        return DeviceIoControl(
            hDevice,
            IOCTL_AUTH,
            &req,
            sizeof(req),
            nullptr,
            0,
            &returned,
            nullptr
        );
    }

    bool Ping()
    {
        DWORD returned;

        return DeviceIoControl(
            hDevice,
            IOCTL_PING,
            nullptr,
            0,
            nullptr,
            0,
            &returned,
            nullptr
        );
    }
};

BOOLEAN IsHvciEnabled()
{
    SYSTEM_CODEINTEGRITY_INFORMATION info;
    RtlZeroMemory(&info, sizeof(info));

    info.Length = sizeof(info);

    NTSTATUS status =
        ZwQuerySystemInformation(
            SystemCodeIntegrityInformation,
            &info,
            sizeof(info),
            NULL
        );

    if (!NT_SUCCESS(status))
        return FALSE;

    if (info.CodeIntegrityOptions &
        CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED)
    {
        return TRUE;
    }

    return FALSE;
}
int main()
{
    SecurityClient client;

    if (!client.Connect())
    {
        std::cout << "Driver not found\n";
        return 1;
    }

    if (!client.Authenticate())
    {
        std::cout << "Auth failed\n";
        return 1;
    }

    std::cout << "Authenticated!\n";

    client.Ping();

    std::cout << "Ping sent\n";
}