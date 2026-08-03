#pragma once

extern "C"
{
	__declspec(dllexport) bool Ping();
	__declspec(dllexport) bool Connect();
	__declspec(dllexport) bool Authenticate();
	__declspec(dllexport) bool SendPrivateKeyToDriver(const char* privateKeyPath, char* mode);
	__declspec(dllexport) bool SendPrivateKeyToDriver(char* privateKey);
}