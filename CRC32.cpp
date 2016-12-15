#include "CRC32.h"

#include <array>
#include <utility>

template <unsigned int C, unsigned int K = 8u>
struct crc32_polynomial // bit-reverse 0x04C11DB7U;
	: crc32_polynomial<((C & 1u) ? 0xEDB88320u : 0u) ^ (C >> 1u), K - 1u>
{ };

template <unsigned int C>
struct crc32_polynomial<C, 0u>
	: std::integral_constant<unsigned int, C>
{ };

template <unsigned int Index>
constexpr auto crc32_polynomial_v = crc32_polynomial<Index>::value;

template <size_t... Indexes>
constexpr auto IndexesToPolynomial(std::index_sequence<Indexes...>) {
	return std::integer_sequence<
		unsigned int, crc32_polynomial<Indexes>::value...>{};
}

template <typename T, size_t... Values>
constexpr auto SequenceToArray(std::integer_sequence<T, Values...>) {
	return std::array<T const, sizeof...(Values)>{ Values... };
}

constexpr auto const crc_table = SequenceToArray(
	IndexesToPolynomial(std::make_index_sequence<256>()));

unsigned int CRC32::compute(
	void const* const buffer, long long const length) noexcept
{
	for(auto i = 0ll; i < length; ++i)
	{
		auto const byte = static_cast<unsigned char const*>(buffer)[i];
		auto const index = static_cast<unsigned char>((_value & 0xFF) ^ byte);
		_value = (_value >> 8) ^ crc_table[index];
	}

	return ~_value;
}
