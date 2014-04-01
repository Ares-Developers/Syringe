#ifndef LOG_H
#define LOG_H

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

	virtual void WriteTimestamp();

public:
	Log(std::string filename) : Filename(std::move(filename)) {}

	virtual void Open();
	virtual void Close();

	virtual void WriteLine();
	virtual void WriteLine(const char*, ...);
	virtual void WriteLine(const char*, va_list);

	static void Select(Log*);
	static void Deselect();

	static void SelOpen();
	static void SelClose();

	static void SelWriteLine();
	static void SelWriteLine(const char*, ...);
};

#endif
