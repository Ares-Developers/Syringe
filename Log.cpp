#pragma warning(disable: 4996)	//unsafe blahblah

#include "Log.h"

Log* Log::sel=NULL;

Log::Log(const char* FileName)
{
	f=NULL;
	strncpy(filename,FileName,LOG_FILENAME_LEN);
}

void Log::Open()
{
	Close();
	if(*filename)f=fopen(filename,"w");
}

void Log::Close()
{
	if(f)
	{
		fclose(f);
		f=NULL;
	}
}

void Log::WriteTimestamp()
{
	if(f)
	{
		time_t raw;
		time(&raw);
		tm* t=localtime(&raw);

		fprintf(f,"[%02d:%02d:%02d] ",t->tm_hour,t->tm_min,t->tm_sec);
		fflush(f);fseek(f,0,SEEK_END);
	}
}

void Log::WriteLine()
{
	if(f)
	{
		fputs("\n",f);
		fflush(f);fseek(f,0,SEEK_END);
	}
}

void Log::WriteLine(const char* Format, ...)
{
	if(f)
	{
		WriteTimestamp();

		va_list args;
		va_start(args,Format);

		if(f)vfprintf(f,Format,args);

		va_end(args);

		WriteLine();
	}
}

void Log::WriteLine(const char* Format,va_list Arguments)
{
	if(f)
	{
		WriteTimestamp();
		vfprintf(f,Format,Arguments);
		WriteLine();
	}
}

void Log::Select(Log* log)
{
	sel=log;
}

void Log::Deselect()
{
	sel=NULL;
}

void Log::SelWriteLine()
{
	if(sel)
		sel->WriteLine();
}

void Log::SelWriteLine(const char* Format,...)
{
	if(sel)
	{
		va_list args;
		va_start(args,Format);

		sel->WriteLine(Format,args);

		va_end(args);
	}
}

void Log::SelOpen()
{
	if(sel)
		sel->Open();
}

void Log::SelClose()
{
	if(sel)
		sel->Close();
}