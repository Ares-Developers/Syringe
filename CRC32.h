#pragma once

class CRC32
{
public:
	unsigned int compute(void const* buffer, long long length) noexcept;

	unsigned int value() const noexcept {
		return ~_value;
	}

	void reset() noexcept {
		_value = 0xFFFFFFFFU;
	}

private:
	unsigned int _value{ 0xFFFFFFFFU };
};
