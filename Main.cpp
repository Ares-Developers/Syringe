#include "SyringeDebugger.h"
#include "Log.h"

#include <string>

auto const VersionString = "Syringe 0.7.0.5";

int Run(char* const lpCmdLine) {
	Log::Open("syringe.log");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	Log::WriteLine();
	Log::WriteLine("WinMain: lpCmdLine = \"%s\"", lpCmdLine);

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

				Log::WriteLine("WinMain: Trying to load executable file \"%s\"...", file.c_str());
				Log::WriteLine();
				SyringeDebugger Debugger;
				if(Debugger.RetrieveInfo(file))
				{
					Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
					Log::WriteLine();
					Debugger.FindDLLs();

					Log::WriteLine("WinMain: SyringeDebugger::Run(\"%s\");", args);
					Log::WriteLine();
					Debugger.Run(args);

					Log::WriteLine("WinMain: SyringeDebugger::Run finished.", args);
					Log::WriteLine("WinMain: Exiting on success.");
					return 0;
				}
				else
				{
					char msg[0x280];
					sprintf_s(msg, "Fatal Error:\r\nCould not load executable file: \"%s\"", file.c_str());

					MessageBoxA(nullptr, msg, "Syringe", MB_OK | MB_ICONERROR);

					Log::WriteLine("WinMain: ERROR: Could not load executable file, exiting...");
				}
			}
			else
			{
				char msg[0x280];
				sprintf_s(msg, "Fatal Error:\r\nCould not evaluate command line arguments: \"%s\"", lpCmdLine);

				MessageBoxA(nullptr, msg, "Syringe", MB_OK | MB_ICONERROR);

				Log::WriteLine("WinMain: ERROR: Command line arguments could not be evaluated, exiting...");
			}
		}
		else
		{
			MessageBoxA(nullptr, "Syringe cannot be run just like that.\r\nPlease run a Syringe control file!",
				VersionString, MB_OK | MB_ICONINFORMATION);

			Log::WriteLine("WinMain: ERROR: No command line arguments given, exiting...");
		}
	}

	Log::WriteLine("WinMain: Exiting on failure.");
	return 0;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	return Run(lpCmdLine);
}
