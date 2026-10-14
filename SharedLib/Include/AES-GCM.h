#pragma once
#include <sal.h>
#include <bcrypt.h>

#ifndef _AES_GCM_
#define _AES_GCM_

constexpr int AES_KEY_SIZE = 32;
constexpr int GCM_NONCE_SIZE = 12;
constexpr int GCM_TAG_SIZE = 16;

#define EAS256_BITS = 256
#define BYTES_PER_BIT = 8
#define AES256_KEY_SIZE (EAS256_BITS / BYTES_PER_BIT)

template<typename T> class AES_GCM
{
private:
	BCRYPT_ALG_HANDLE _algorithm = nullptr;
	BCRYPT_KEY_HANDLE _aesKey = nullptr;
private: 
	void Cleanup()
	{
		if (_aesKey)
		{
			BCryptDestroyKey(_aesKey);
			_aesKey = nullptr;
		}

		if (_algorithm)
		{
			BCryptCloseAlgorithmProvider(_algorithm, 0);
			_algorithm = nullptr;
		}
	}
	bool Initialize(_In_reads_bytes_(AES256_KEY_SIZE) unsigned char* key)
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(&_algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
		if (!BCRYPT_SUCCESS(status))
			return false;
		status = BCryptSetProperty(_algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<unsigned char*>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
		if (!BCRYPT_SUCCESS(status))
		{
			Cleanup();
			return false;
		}
		status = BCryptGenerateSymmetricKey(_algorithm, &_aesKey, nullptr, 0, const_cast<unsigned char*>(key), AES256_KEY_SIZE, 0);
		if (!BCRYPT_SUCCESS(status))
		{
			Cleanup();
			return false;
		}
		Cleanup();
		return true;
	}

public:
	AES_GCM(unsigned char* key)
	{
		Initialize(key);
	}
	bool Encrypt(_In_ PUCHAR tag, _In_ PUCHAR nonce, _Inout_ PUCHAR* buffer, _Inout_ PULONG* size) {
		PUCHAR inputCopy;
		memcpy(&inputCopy, &buffer, sizeof(buffer));

		NTSTATUS status = BCryptGenRandom(nullptr, obj.nonce, GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (!BCRYPT_SUCCESS(status))
		{
			Cleanup();
			return false;
		}

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = nonce;
		authInfo.cbNonce = GCM_NONCE_SIZE;
		authInfo.pbTag = tag;
		authInfo.cbTag = GCM_TAG_SIZE;

		//unsigned long encryptedSize = 0;
		status = BCryptEncrypt(_aesKey, inputCopy, sizeof(inputCopy), &authInfo, nullptr, 0, buffer, sizeof(buffer), &size, 0);
		//obj.ciphertextSize = encryptedSize;

		Cleanup();
		return true;
	}
	bool Decrypt(_In_ PUCHAR tag, _In_ PUCHAR nonce, _Inout_ PUCHAR* buffer, _Inout_ PULONG* size)
	{
		PUCHAR inputCopy;
		memcpy(&inputCopy, &buffer, sizeof(buffer));

		bool result;
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = nonce;
		authInfo.cbNonce = GCM_NONCE_SIZE;
		authInfo.pbTag = tag;
		authInfo.cbTag = GCM_TAG_SIZE;

		ULONG* decryptedSize = 0;

		NTSTATUS status = BCryptDecrypt(_aesKey, inputCopy, sizeof(inputCopy), &authInfo, nullptr, 0, buffer, &size, &decryptedSize, 0);
		if (BCRYPT_SUCCESS(status) || *decryptedSize != *size)
		{
			result = true;
		}
		
		Cleanup();
		return result;
	}
};
#endif 