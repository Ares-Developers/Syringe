#include "Log.h"
#include "SyringeDebugger.h"

#include <string>

#include <commctrl.h>

inline auto GetLastErrorMessage(DWORD const error = GetLastError())
{
	struct lasterror {
		DWORD error;
		std::string message;

		explicit operator bool() const noexcept {
			return this->error != ERROR_SUCCESS;
		}
	} ret{ error };

	LocalAllocHandle handle;

	auto count = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPTSTR>(handle.set()), 0u, nullptr);

	auto const message = static_cast<LPTSTR>(handle.get());
	while(count && isspace(static_cast<unsigned char>(message[count - 1]))) {
		--count;
	}

	ret.message.assign(message, count);

	return ret;
}

int Run(char* const lpCmdLine) {
	constexpr auto const VersionString = "Syringe 0.7.0.6";

	InitCommonControls();

	Log::Open("syringe.log");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	Log::WriteLine();
	Log::WriteLine("WinMain: lpCmdLine = \"%s\"", lpCmdLine);

	if(lpCmdLine && *lpCmdLine == '\"')
	{
		auto const pFilenameBegin = lpCmdLine + 1;

		if(auto const pFilenameEnd = strstr(pFilenameBegin, "\""))
		{
			std::string file(pFilenameBegin, pFilenameEnd);
			auto failure = "Could not load executable.";
			
			Log::WriteLine("WinMain: Trying to load executable file \"%s\"...", file.c_str());
			Log::WriteLine();
			SyringeDebugger Debugger;
			if(Debugger.RetrieveInfo(file))
			{
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
			}

			auto exit_code = ERROR_ERRORS_ENCOUNTERED;
			if(auto const lasterror = GetLastErrorMessage()) {
				Log::WriteLine("WinMain: %s (%d)", lasterror.message.c_str(), lasterror.error);

				auto const msg = std::string(failure) + "\n\n\"" + file + "\"\n\n" + lasterror.message;
				MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

				exit_code = lasterror.error;
			}

			Log::WriteLine("WinMain: Exiting on failure.");
			return exit_code;
		}
	}

	// if this code is reached, the arguments couldn't be parsed
	MessageBoxA(nullptr, "Syringe cannot be run just like that.\n\nUsage:\nSyringe.exe \"<exe name>\" <arguments>",
		VersionString, MB_OK | MB_ICONINFORMATION);

	Log::WriteLine("WinMain: No or invalid command line arguments given, exiting...");
	Log::WriteLine("WinMain: Exiting on failure.");
	return ERROR_INVALID_PARAMETER;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	return Run(lpCmdLine);
}
