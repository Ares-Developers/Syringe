#include "CRC32.h"

unsigned int CRC32::table[256];
bool CRC32::initialized = false;

CRC32::CRC32() noexcept
{
	if(!initialized)
	{
		initialize();
	}

	reset();
}

void CRC32::initialize() noexcept
{
	for(unsigned int i = 0; i < 256; ++i)
	{
		unsigned int value = i;

		for(int j = 8; j > 0; --j)
		{
			if(value & 1)
			{
				value = (value >> 1) ^ polynomial;
			}
			else
			{
				value = (value >> 1);
			}
		}

		table[i] = value;
	}

	initialized = true;
}

unsigned int CRC32::compute(void* buffer, long long length) noexcept
{
	for(long long i = 0; i < length; ++i)
	{
		unsigned char byte = static_cast<unsigned char*>(buffer)[i];
		unsigned char index = (_value & 0xFF) ^ byte;
		_value = (_value >> 8) ^ table[index];
	}

	return ~_value;
}
