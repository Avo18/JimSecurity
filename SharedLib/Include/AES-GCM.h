#pragma once
#include <sal.h>
#include <bcrypt.h>

#ifndef _AES-GCM_
#define _AES-GCM_

constexpr int AES_KEY_SIZE = 32;
constexpr int GCM_NONCE_SIZE = 12;
constexpr int GCM_TAG_SIZE = 16;

#define EAS256_BITS = 256
#define BYTES_PER_BIT = 8
#define AES256_KEY_SIZE (EAS256_BITS / BYTES_PER_BIT)

class AES_GCM
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

public:
	bool Initialize(_In_reads_bytes_(AES256_KEY_SIZE) const unsigned char* key)
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
		return true;

	}
	template<typename T> bool Encrypt(_Inout_ T& obj) {

		NTSTATUS status = BCryptGenRandom(nullptr, obj.nonce,	GCM_NONCE_SIZE,	BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (!BCRYPT_SUCCESS(status))
		{
			Cleanup();
			return false;
		}

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = obj.nonce;
		authInfo.cbNonce = GCM_NONCE_SIZE;
		authInfo.pbTag = obj.tag;
		authInfo.cbTag = GCM_TAG_SIZE;

		unsigned long encryptedSize = 0;
		status = BCryptEncrypt(aesKey, reinterpret_cast<unsigned char*>(const_cast<T*>(&obj)), sizeof(obj), &authInfo, nullptr, 0, obj.ciphertext, sizeof(obj.ciphertext), &encryptedSize, 0);
		obj.ciphertextSize = encryptedSize;

		Cleanup();
		return true;
	}
	template<typename T> bool Decrypt(_Inout_ T& obj)
	{
		bool result;
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = const_cast<unsigned char*>(obj.nonce);
		authInfo.cbNonce = GCM_NONCE_SIZE;
		authInfo.pbTag = const_cast<unsigned char*>(obj.tag);
		authInfo.cbTag = GCM_TAG_SIZE;

		ULONG decryptedSize = 0;

		NTSTATUS status = BCryptDecrypt(aesKey, const_cast<unsigned char*>(input.ciphertext), input.ciphertextSize, &authInfo, nullptr, 0, reinterpret_cast<unsigned char*>(&obj), sizeof(obj), &decryptedSize, 0);
		if (!BCRYPT_SUCCESS(status) || decryptedSize != sizeof(T))
		{
			result = false;
		}
		else
		{
			result = true;
		}
		Cleanup();
		return true;
	}
};
#endif 