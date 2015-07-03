#include "SyringeDebugger.h"
#include "Log.h"

#include <string>

auto const VersionString = "Syringe 0.7.0.5";

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	Log log("syringe.log");
	Log::Select(&log);

	Log::SelOpen();

	Log::SelWriteLine(VersionString);
	Log::SelWriteLine("===============");
	Log::SelWriteLine();
	Log::SelWriteLine("WinMain: lpCmdLine = \"%s\"", lpCmdLine);

	if(lpCmdLine)
	{
		if(strstr(lpCmdLine, "\"") == lpCmdLine)
		{
			char* fn = lpCmdLine + 1;
			char* args = strstr(fn, "\"");

			if(args)
			{
				std::string file(fn, static_cast<unsigned int>(args - fn));
				++args;

				Log::SelWriteLine("WinMain: Trying to load executable file \"%s\"...", file.c_str());
				Log::SelWriteLine();
				SyringeDebugger Debugger;
				if(Debugger.RetrieveInfo(file))
				{
					Log::SelWriteLine("WinMain: SyringeDebugger::FindDLLs();");
					Log::SelWriteLine();
					Debugger.FindDLLs();

					Log::SelWriteLine("WinMain: SyringeDebugger::Run(\"%s\");", args);
					Log::SelWriteLine();
					Debugger.Run(args);

					Log::SelWriteLine("WinMain: SyringeDebugger::Run finished.", args);
					Log::SelWriteLine("WinMain: Exiting on success.");
					Log::SelClose();
					return 0;
				}
				else
				{
					char msg[0x280] = "\0";
					sprintf_s(msg, "Fatal Error:\r\nCould not load executable file: \"%s\"", file.c_str());

					MessageBoxA(nullptr, msg, "Syringe", MB_OK | MB_ICONERROR);

					Log::SelWriteLine("WinMain: ERROR: Could not load executable file, exiting...");
				}
			}
			else
			{
				char msg[0x280] = "\0";
				sprintf_s(msg, "Fatal Error:\r\nCould not evaluate command line arguments: \"%s\"", lpCmdLine);

				MessageBoxA(nullptr, msg, "Syringe", MB_OK | MB_ICONERROR);

				Log::SelWriteLine("WinMain: ERROR: Command line arguments could not be evaluated, exiting...");
			}
		}
		else
		{
			MessageBoxA(nullptr, "Syringe cannot be run just like that.\r\nPlease run a Syringe control file!",
				VersionString, MB_OK | MB_ICONINFORMATION);

			Log::SelWriteLine("WinMain: ERROR: No command line arguments given, exiting...");
		}
	}

	Log::SelWriteLine("WinMain: Exiting on failure.");
	Log::SelClose();
	return 0;
}
