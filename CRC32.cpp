#include "CRC32.h"

#include <array>

constexpr auto create_crc_table() noexcept {
	std::array<unsigned int, 256> ret{};

	for(auto i = 0u; i < 256u; ++i) {
		auto value = i;

		for(auto j = 8u; j; --j) {
			// bit-reverse 0x04C11DB7U;
			auto const polynomial = (value & 1u) ? 0xEDB88320u : 0u;
			value = (value >> 1u) ^ polynomial;
		}

		ret[i] = value;
	}

	return ret;
}

unsigned int CRC32::compute(
	void const* const buffer, long long const length) noexcept
{
	static constexpr auto const crc_table = create_crc_table();

	auto const data = static_cast<unsigned char const*>(buffer);

	for(auto i = data; i < &data[length]; ++i) {
		auto const index = static_cast<unsigned char>((_value & 0xFFu) ^ *i);
		_value = (_value >> 8u) ^ crc_table[index];
	}

	return ~_value;
}
