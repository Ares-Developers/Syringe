#pragma once

#include "Handle.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <string>

class Log
{
private:
	FileHandle File;
	std::string Filename;

	static Log* sel;

	void WriteTimestamp();

public:
	Log(std::string filename) : Filename(std::move(filename)) {}

	void Open();
	void Close();

	void WriteLine();
	void WriteLine(const char*, ...);
	void WriteLine(const char*, va_list);

	static void Select(Log*);
	static void Deselect();

	static void SelOpen();
	static void SelClose();

	static void SelWriteLine();
	static void SelWriteLine(const char*, ...);
};
