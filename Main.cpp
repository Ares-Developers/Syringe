#pragma warning(disable: 4786)	/*That fucking "warning" annoyed me...
								  I recommend using this if you use std::map -pd*/
#pragma warning(disable: 4996)	//unsafe blahblah

#include "SyringeDebugger.h"
#include "Log.h"

#define VERSION_STRING	"Syringe 0.7.0.1"

SyringeDebugger Debugger;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	Log* log=new Log("syringe.log");
	Log::Select(log);

	Log::SelOpen();

	Log::SelWriteLine(VERSION_STRING);
	Log::SelWriteLine("===============");
	Log::SelWriteLine();
	Log::SelWriteLine("WinMain: lpCmdLine = \"%s\"",lpCmdLine);

	if(lpCmdLine)
	{
		char file[0x200]="\0";

		if(strstr(lpCmdLine,"\"")==lpCmdLine)
		{
			char* fn=lpCmdLine+1;
			char* args=strstr(fn,"\"");

			if(args)
			{
				strncpy(file,fn,(DWORD)args-(DWORD)fn);
				++args;

				Log::SelWriteLine("WinMain: Trying to load executable file \"%s\"...",file);
				Log::SelWriteLine();
				if(Debugger.RetrieveInfo(file))
				{
					Log::SelWriteLine("WinMain: SyringeDebugger::FindDLLs();");
					Log::SelWriteLine();
					Debugger.FindDLLs();

					Log::SelWriteLine("WinMain: SyringeDebugger::Run(\"%s\");",args);
					Log::SelWriteLine();
					Debugger.Run(args);

					Log::SelWriteLine("WinMain: SyringeDebugger::Run finished.",args);
					Log::SelWriteLine("WinMain: Exiting on success.");
					Log::SelClose();
					return 0;
				}
				else
				{
					char msg[0x280]="\0";

					sprintf(
						msg,
						"Fatal Error:\r\nCould not load executable file: \"%s\"",
						file);

					MessageBoxA(
						NULL,
						msg,
						"Syringe",
						MB_OK|MB_ICONERROR);

					Log::SelWriteLine("WinMain: ERROR: Could not load executable file, exiting...",file);
				}
			}
			else
			{
				char msg[0x280]="\0";

				sprintf(
					msg,
					"Fatal Error:\r\nCould not evaluate command line arguments: \"%s\"",
					lpCmdLine);

				MessageBoxA(
					NULL,
					msg,
					"Syringe",
					MB_OK|MB_ICONERROR);

				Log::SelWriteLine("WinMain: ERROR: Command line arguments could not be evaluated, exiting...");
			}
		}
		else
		{
			MessageBoxA(
				NULL,
				"Syringe cannot be run just like that.\r\nPlease run a Syringe control file!",
				VERSION_STRING,
				MB_OK|MB_ICONINFORMATION);

			Log::SelWriteLine("WinMain: ERROR: No command line arguments given, exiting...");
		}
	}
	
	Log::SelWriteLine("WinMain: Exiting on failure.");
	Log::SelClose();
	return 0;
}
