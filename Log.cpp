#include "Log.h"
#include <share.h>

Log* Log::sel = nullptr;

void Log::Open()
{
	Close();
	if(!this->Filename.empty()) {
		this->File = FileHandle(_fsopen(this->Filename.c_str(), "w", _SH_DENYWR));
	}
}

void Log::Close()
{
	this->File.clear();
}

void Log::WriteTimestamp()
{
	if(this->File) {
		time_t raw;
		time(&raw);

		tm t;
		localtime_s(&t, &raw);

		fprintf(this->File, "[%02d:%02d:%02d] ", t.tm_hour, t.tm_min, t.tm_sec);
		fflush(this->File);
		fseek(this->File, 0, SEEK_END);
	}
}

void Log::WriteLine()
{
	if(this->File)
	{
		fputs("\n", this->File);
		fflush(this->File);
		fseek(this->File, 0, SEEK_END);
	}
}

void Log::WriteLine(const char* Format, ...)
{
	if(this->File) {
		WriteTimestamp();

		va_list args;
		va_start(args, Format);

		if(this->File) {
			vfprintf(this->File, Format, args);
		}

		va_end(args);

		WriteLine();
	}
}

void Log::WriteLine(const char* Format, va_list Arguments)
{
	if(this->File) {
		WriteTimestamp();
		vfprintf(this->File, Format, Arguments);
		WriteLine();
	}
}

void Log::Select(Log* log)
{
	sel = log;
}

void Log::Deselect()
{
	sel = nullptr;
}

void Log::SelWriteLine()
{
	if(sel) {
		sel->WriteLine();
	}
}

void Log::SelWriteLine(const char* Format, ...)
{
	if(sel) {
		va_list args;
		va_start(args, Format);

		sel->WriteLine(Format, args);

		va_end(args);
	}
}

void Log::SelOpen()
{
	if(sel) {
		sel->Open();
	}
}

void Log::SelClose()
{
	if(sel) {
		sel->Close();
	}
}
