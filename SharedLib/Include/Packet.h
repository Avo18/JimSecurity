#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
//#include <type_traits>

//#ifndef _Packet_
//#define _PACKET_
//
//typedef unsigned long DWORD;
//typedef unsigned char WORD;
//#define MAX_PACKET_SIZE 256
//
//const int SESSION_KEY_LENTH = 16;

namespace Shared
{
	using Byte = std::uint8_t;
	using PacketSize = std::uint32_t;

	constexpr std::size_t MAX_PACKET_SIZE = 256;
	constexpr std::size_t SESSION_KEY_LENGTH = 16;

	class Packet
	{
	public:
		Packet(DWORD command) {
			_command = command;
		}
		template<typename T> bool Add(T value) {
			if (_size + sizeof(T) > MAX_PACKET_SIZE)
				return false;

			*((T*)&_packet[_size]) = value;
			_size += sizeof(T);
			return true;
		}
		inline bool AddString(const char* str, bool endStr = true)
		{
			size_t lengte = strlen(str);

			if (_size + lengte + 1 > MAX_PACKET_SIZE)
				return false;

			memcpy_s(_packet + _size, MAX_PACKET_SIZE - _size, str, lengte);
			_size += lengte;
			if (endStr) {
				_data[_size++] = '\0';
			}
			return true;
		}

		inline bool AddBytes(const __int8* bytes, size_t length)
		{
			if (_size + length > MAX_PACKET_SIZE)
				return false;
			memcpy_s(_packet + _size, MAX_PACKET_SIZE - _size, bytes, length);
			_size += length;
			return true;
		}

		void AddAuthenticationTag(const __int8* tag)
		{
			const int tagSize = 16;
			if (_size + tagSize > MAX_PACKET_SIZE)
				return;

			memcpy(_packet + _size, tag, tagSize);
			_size += tagSize;
		}
		void RandomNonce()
		{
			_nonce = new PUCHAR[10];
			for (int i = 0; i < 10; i++)
			{
				//_nonce[i] = rand() % 256;
			}
		}
		void SetSize(PULONG packetSize)
		{
			_packetSize = packetSize;
		}

		template<typename T> T Get(int index) const {
			return *((T*)&_data[index]);
		}
		template<typename T> void Set(int index, T value) {
			*((T*)&_data[index]) = value;
		}
		inline const WORD* GetData() const { return _packet; }
		inline int GetSize() const { return _size; }
		inline int GetCommand() const { return _command; }
		PULONG GetPacketSize() const { return _packetSize; }
		PUCHAR* GetNonce() const { return _nonce; }
		PUCHAR* GetTag() const { return _tag; }
	private:
		union
		{
			struct {
				int _command;
				int _size;
				WORD _data[1];
			};
			WORD _packet[MAX_PACKET_SIZE];
		};
		PUCHAR* _nonce;
		PUCHAR* _tag;
		PULONG _packetSize;
	};
}
//#endif