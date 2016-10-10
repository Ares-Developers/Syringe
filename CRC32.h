#pragma once

class CRC32
{
public:
	CRC32() noexcept;

	unsigned int compute(void* buffer, long long length) noexcept;

	unsigned int value() const noexcept {
		return ~_value;
	}

	void reset() noexcept {
		_value = 0xFFFFFFFFU;
	}

private:
	static void initialize() noexcept;

	static bool initialized;
	static unsigned int table[256];

	unsigned int _value{ 0xFFFFFFFFU };

	static const unsigned int polynomial = 0xEDB88320U; // bit-reverse 0x04C11DB7U;
};
