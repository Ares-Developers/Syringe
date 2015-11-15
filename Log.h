#pragma once

#include "Handle.h"

class Log
{
private:
	static FileHandle File;

	static void WriteTimestamp() noexcept;

public:
	static void Open(char const* pFilename) noexcept;

	static void WriteLine() noexcept;
	static void WriteLine(const char* pFormat, ...) noexcept;
};
