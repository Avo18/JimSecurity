#pragma once
#include <string.h>

#ifndef _Packet_
#define _PACKET_

typedef unsigned long DWORD;
typedef unsigned char WORD;
#define MAX_PACKET_SIZE 256

namespace Shared
{
	class Packet
	{
	public:
		Packet(DWORD command) {
			_command = command;
		}
		template<typename T> bool Add(T value) {
			if (_size + sizeof(T) > MAX_PACKET_SIZE)
				return false;

			*((T*)&_packet[_size]) = val;
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
		void AddAuthenticationTag(const __int8* tag)
		{
			const int tagSize = 16;
			if (_size + tagSize > MAX_PACKET_SIZE)
				return;

			memcpy(_packet + _size, tag, tagSize);
			_size += tagSize;
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

	private:
		union
		{
			struct {
				int _command;
				int _size;
				int _capacity;
				WORD _data[1];
			};
			WORD _packet[MAX_PACKET_SIZE];
		};
	};
}
#endif