#pragma once

class CRC32
{
public:
	CRC32();

	unsigned int compute(void* buffer, long long length);
	unsigned int value() const;
	void reset();

private:
	static void initialize();

	static bool initialized;
	static unsigned int table[256];

	unsigned int _value;

	static const unsigned int polynomial = 0xEDB88320U; // bit-reverse 0x04C11DB7U;
};
