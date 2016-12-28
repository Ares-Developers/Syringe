#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"

#include <string>

#include <commctrl.h>

int Run(char* const lpCmdLine) {
	constexpr auto const VersionString = "Syringe 0.7.0.6";

	InitCommonControls();

	Log::Open("syringe.log");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	Log::WriteLine();
	Log::WriteLine("WinMain: lpCmdLine = \"%s\"", lpCmdLine);

	auto failure = "Could not load executable.";
	auto exit_code = ERROR_ERRORS_ENCOUNTERED;

	try
	{
		if(lpCmdLine && *lpCmdLine == '\"')
		{
			auto const pFilenameBegin = lpCmdLine + 1;

			if(auto const pFilenameEnd = strstr(pFilenameBegin, "\""))
			{
				std::string_view file(pFilenameBegin, pFilenameEnd - pFilenameBegin);

				Log::WriteLine("WinMain: Trying to load executable file \"%.*s\"...", printable(file));
				Log::WriteLine();

				SyringeDebugger Debugger;
				Debugger.RetrieveInfo(file);
				failure = "Could not run executable.";

				Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
				Log::WriteLine();
				Debugger.FindDLLs();

				auto const pArgs = &pFilenameEnd[1 + strspn(pFilenameEnd + 1, " ")];
				Log::WriteLine("WinMain: SyringeDebugger::Run(\"%s\");", pArgs);
				Log::WriteLine();

				if(Debugger.Run(pArgs)) {
					Log::WriteLine("WinMain: SyringeDebugger::Run finished.");
					Log::WriteLine("WinMain: Exiting on success.");
					return ERROR_SUCCESS;
				}

				// something went wrong
				throw_lasterror_or(exit_code, std::string(file));
			}
		}

		// if this code is reached, the arguments couldn't be parsed
		throw invalid_command_arguments{};
	}
	catch(lasterror const& e)
	{
		Log::WriteLine("WinMain: %s (%d)", e.message.c_str(), e.error);

		auto const msg = std::string(failure) + "\n\n" + e.message;
		MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

		exit_code = e.error;
	}
	catch(invalid_command_arguments const& e)
	{
		MessageBoxA(
			nullptr, "Syringe cannot be run just like that.\n\n"
			"Usage:\nSyringe.exe \"<exe name>\" <arguments>",
			VersionString, MB_OK | MB_ICONINFORMATION);

		Log::WriteLine(
			"WinMain: No or invalid command line arguments given, exiting...");

		exit_code = ERROR_INVALID_PARAMETER;
	}

	Log::WriteLine("WinMain: Exiting on failure.");
	return exit_code;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	return Run(lpCmdLine);
}
