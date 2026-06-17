#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>

//#include <ntddk.h>


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

    BOOLEAN VerifyClient(BYTE* signature)
    {

        BOOLEAN result;


     /*   result =
            VerifySignature(
                PublicKey,
                gSession.Challenge,
                signature
            );*/


        return result;

    }
    /// <summary>
    /// Private key check voor de client
    /// </summary>
    /// <param name="challenge"></param>
    /// <param name="signature"></param>
    /// <returns></returns>
    bool SignChallenge(BYTE* challenge, BYTE* signature)
    {
        // Moet nog geimplementeerd worden, dit is een placeholder
		// RSA_SIGN = haalt uw private key op en signeert de challenge, en verstuurd de signature terug naar de driver.
        // die deze zal verifiëren met de public key die in de driver is opgeslagen
		RSA_sign(challenge, signature); 

        return true;
    }

    void RSA_sign(BYTE* challenge, BYTE* signature)
    {
		LoadPrivateKey();

    }
    void sendToDriver()
    {
    /*    DWORD bytes;
        DeviceIoControl(
            hDriver,
            IOCTL_AUTH_RESPONSE,
            &response,
            sizeof(response),
            nullptr,
            0,
            &bytes,
            nullptr
        );*/
    }

    EVP_PKEY* LoadPrivateKey()
    {
        FILE* file = fopen("private.pem", "rb");

        if (!file)
            return nullptr;

        EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);

        fclose(file);
	
        return key;
    }

    bool SignChallenge(unsigned char* challenge, size_t challengeSize, unsigned char* signature, size_t* signatureSize)
    {
        EVP_PKEY* privateKey = LoadPrivateKey();

        if (!privateKey)
            return false;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey);
        EVP_DigestSignUpdate(ctx, challenge, challengeSize);

        EVP_DigestSignFinal(ctx, signature, signatureSize);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return true;
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