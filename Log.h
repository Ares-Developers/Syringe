#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define LOG_FILENAME_LEN	0x200

class Log
{
private:
	FILE* f;
	char filename[LOG_FILENAME_LEN];

	static Log* sel;

	virtual void WriteTimestamp();

public:
	Log(const char*);

	virtual void Open();
	virtual void Close();

	virtual void WriteLine();
	virtual void WriteLine(const char*,...);
	virtual void WriteLine(const char*,va_list);

	static void Select(Log*);
	static void Deselect();

	static void SelOpen();
	static void SelClose();

	static void SelWriteLine();
	static void SelWriteLine(const char*,...);
};

#endif