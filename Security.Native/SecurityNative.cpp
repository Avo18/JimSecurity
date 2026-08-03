#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <winioctl.h>

BCRYPT_ALG_HANDLE _algHandle = NULL;
BCRYPT_KEY_HANDLE _publicKey = NULL;


#define IOCTL_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOAD_KEY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_WRITE_DATA)

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
    HANDLE handleDevice;

public:

    bool Connect()
    {
        handleDevice = CreateFileW(
            L"\\\\.\\JimSecurity",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        return handleDevice != INVALID_HANDLE_VALUE;
    }

    bool Authenticate()
    {
        AUTH_REQUEST req = {};
        req.Magic = DRIVER_MAGIC;
        req.ClientId = GetCurrentProcessId();

        DWORD returned;

        return DeviceIoControl(
            handleDevice,
            IOCTL_AUTH,
            &req,
            sizeof(req),
            nullptr,
            0,
            &returned,
            nullptr
        );
    }

    NTSTATUS Init()
    {
        return BCryptOpenAlgorithmProvider(&_algHandle, BCRYPT_RSA_ALGORITHM, NULL, 0);
    }
    NTSTATUS LoadPublicKey(PUCHAR keyBlob, ULONG keyBlobSize)
    {
        if (!_algHandle)
            return STATUS_INVALID_HANDLE;
    
        NTSTATUS status = BCryptImportKeyPair(_algHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, &_publicKey, keyBlob, keyBlobSize, 0);
    
        return status;
    }

	bool SendPrivateKeyToDriver(const char* privateKeyPath, char* mode)
	{
		FILE* file = fopen(privateKeyPath, mode);
		if (!file)
			return false;
        EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        if (!key) return false;

		long keySize = i2d_PrivateKey(key, nullptr);
		unsigned char* keyBuffer = new unsigned char[keySize];
        i2d_PrivateKey(key, &keyBuffer);
		fclose(file);
		DWORD returned;
		bool result = DeviceIoControl(
			handleDevice,
			IOCTL_LOAD_KEY,
			keyBuffer,
			keySize,
			nullptr,
			0,
			&returned,
			nullptr
		);
		delete[] keyBuffer;
		return result;
	}
    bool SendPrivateKeyToDriver(char* privateKey)
    {
        if (!privateKey)
            return false;

        size_t keySize = strlen(privateKey);

        DWORD returned;
        bool result = DeviceIoControl(
            handleDevice,
            IOCTL_LOAD_KEY,
            privateKey,
            keySize,
            nullptr,
            0,
            &returned,
            nullptr
        );
        return result;
    }


    bool SignChallenge(unsigned char* challenge, size_t challengeSize, unsigned char* signature, size_t* signatureSize)
    {
    //    EVP_PKEY* privateKey = LoadPrivateKey();

    //    if (!privateKey)
    //        return false;

    //    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    //    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey);
    //    EVP_DigestSignUpdate(ctx, challenge, challengeSize);

    //    EVP_DigestSignFinal(ctx, signature, signatureSize);

    //    EVP_MD_CTX_free(ctx);
    //    EVP_PKEY_free(privateKey);

        return true;
    }

    bool Ping()
    {
        DWORD returned;

        return DeviceIoControl(
            handleDevice,
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