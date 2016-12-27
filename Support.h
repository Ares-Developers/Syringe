#pragma once

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <Windows.h>

struct invalid_command_arguments : std::exception {};

// returns something %.*s can format
inline auto printable(std::string_view const string) {
	return std::make_pair(string.size(), string.data());
}

inline auto GetFormatMessage(DWORD const error) {
	LocalAllocHandle handle;

	auto count = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPTSTR>(handle.set()), 0u, nullptr);

	auto const message = static_cast<LPTSTR>(handle.get());
	while(count && isspace(static_cast<unsigned char>(message[count - 1]))) {
		--count;
	}

	return std::string(message, count);
}

struct lasterror : std::exception {
	lasterror(DWORD const error)
		: error(error)
	{ }

	lasterror(DWORD const error, std::string insert)
		: error(error),	insert(std::move(insert))
	{ }

	DWORD error{ 0 };
	std::string message{ GetFormatMessage(error) };
	std::string insert;
};

[[noreturn]] inline void throw_lasterror(DWORD error_code, std::string insert) {
	throw lasterror(error_code, std::move(insert));
}

[[noreturn]] inline void throw_lasterror_or(
	DWORD alterative, std::string insert)
{
	auto const error_code = GetLastError();
	throw_lasterror(
		error_code ? error_code : alterative, std::move(insert));
}
