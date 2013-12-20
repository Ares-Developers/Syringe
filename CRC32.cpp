#include "CRC32.h"

unsigned int CRC32::table[256];
bool CRC32::initialized = false;

CRC32::CRC32()
{
	if(!initialized)
	{
		initialize();
	}

	reset();
}

void CRC32::reset()
{
	_value = 0xFFFFFFFFU;
}

void CRC32::initialize()
{
	for(int i = 0; i<256; ++i)
	{
		unsigned int value = i;

		for(int j = 8; j>0; --j)
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

unsigned int CRC32::compute(void* buffer, long long length)
{
	for(long long i = 0; i < length; ++i)
	{
		unsigned char byte = static_cast<char*>(buffer)[i];
		unsigned char index = (_value & 0xFF) ^ byte;
		_value = (_value >> 8) ^ table[index];
	}

	return ~_value;
}

unsigned int CRC32::value() const
{
	return ~_value;
}
