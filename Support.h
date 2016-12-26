#pragma once

#include <string_view>
#include <utility>

// returns something %.*s can format
inline auto printable(std::string_view const string) {
	return std::make_pair(string.size(), string.data());
}
