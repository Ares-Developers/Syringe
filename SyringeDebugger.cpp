#include "SyringeDebugger.h"
#include "Handle.h"
#include "FindFile.h"
#include "Log.h"
#include "CRC32.h"

#include <fstream>
#include <memory>
#include <DbgHelp.h>

using namespace std;

bool SyringeDebugger::DebugProcess(const char* exeFile, char* params)
{
	STARTUPINFO startupInfo;

	memset(&startupInfo, 0, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

	bool retVal = (CreateProcess(
		exeFile, params, nullptr, nullptr, false,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
		nullptr, nullptr, &startupInfo, &pInfo) != FALSE);

	return retVal;
}

bool SyringeDebugger::PatchMem(void* address, const void* buffer, DWORD size)
{
	return (WriteProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

bool SyringeDebugger::ReadMem(const void* address, void* buffer, DWORD size)
{
	return (ReadProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

VirtualMemoryHandle SyringeDebugger::AllocMem(void* address, size_t size)
{
	return VirtualMemoryHandle(pInfo.hProcess, address, size);
}

bool SyringeDebugger::SetBP(void* address)
{
	//save overwritten code and set INT 3
	auto& opcode = bpMap[address].original_opcode;

	if(opcode == 0x00)
	{
		BYTE buffer = INT3;
		ReadMem(address, &opcode, 1);
		return PatchMem(address, &buffer, 1);
	}
	return true;
}

DWORD __fastcall SyringeDebugger::RelativeOffset(const void* pFrom, const void* pTo)
{
	auto const from = reinterpret_cast<DWORD>(pFrom);
	auto const to = reinterpret_cast<DWORD>(pTo);

	return to - from;
}

DWORD SyringeDebugger::HandleException(const DEBUG_EVENT& dbgEvent)
{
	DWORD exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	if(exceptCode == EXCEPTION_BREAKPOINT)
	{
		auto& threadInfo = threadInfoMap[dbgEvent.dwThreadId];
		HANDLE currentThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(currentThread, &context);

		//Entry BP
		if(bEntryBP)
		{
			bEntryBP = false;
			return DBG_CONTINUE;
		}

		//fix single step repetition issues
		if(context.EFlags & 0x100)
		{
			BYTE buffer = INT3;
			context.EFlags &= ~0x100;
			PatchMem(threadInfo.lastBP, &buffer, 1);
		}

		//Load DLLs and retrieve proc addresses
		if(!bDLLsLoaded)
		{
			//Restore
			PatchMem(exceptAddr, &bpMap[exceptAddr].original_opcode, 1);

			if(loop_LoadLibrary == v_AllHooks.end())
				loop_LoadLibrary = v_AllHooks.begin();
			else
			{
				const auto& hook = *loop_LoadLibrary;
				ReadMem(pdProcAddress, &hook->proc_address, 4);

				if(!hook->proc_address) {
					Log::WriteLine(
						"SyringeDebugger::HandleException: Could not retrieve ProcAddress for: %s - %s",
						hook->lib, hook->proc);
				}

				++loop_LoadLibrary;
			}

			if(loop_LoadLibrary != v_AllHooks.end())
			{
				const auto& hook = *loop_LoadLibrary;
				PatchMem(pdLibName, hook->lib, MaxNameLength);
				PatchMem(pdProcName, hook->proc, MaxNameLength);

				context.Eip = reinterpret_cast<DWORD>(pcLoadLibrary);
			}
			else
			{
				Log::WriteLine("SyringeDebugger::HandleException: Finished retrieving proc addresses.");
				bDLLsLoaded = true;

				context.Eip = reinterpret_cast<DWORD>(pcEntryPoint);
			}

			//single step mode
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		}

		if(exceptAddr == pcEntryPoint)
		{
			if(!bHooksCreated)
			{
				Log::WriteLine("SyringeDebugger::HandleException: Creating code hooks.");

				static const BYTE code_call[] =
				{
					0x60, 0x9C, //PUSHAD, PUSHFD
					0x68, INIT, INIT, INIT, INIT, //PUSH HookAddress
					0x54, //PUSH ESP
					0xE8, INIT, INIT, INIT, INIT, //CALL ProcAddress
					0x83, 0xC4, 0x08, //ADD ESP, 8
					0xA3, INIT, INIT, INIT, INIT, //MOV ds:ReturnEIP, EAX
					0x9D, 0x61, //POPFD, POPAD
					0x83, 0x3D, INIT, INIT, INIT, INIT, 0x00, //CMP ds:ReturnEIP, 0
					0x74, 0x06, //JZ .proceed
					0xFF, 0x25, INIT, INIT, INIT, INIT, //JMP ds:ReturnEIP
				};

				static const BYTE jmp_back[] = {0xE9, INIT, INIT, INIT, INIT, };
				static const BYTE jmp[] = {0xE9, INIT, INIT, INIT, INIT, };

				std::vector<BYTE> over;

				for(auto& it : bpMap)
				{
					if(it.first && it.first != pcEntryPoint && it.second.hooks.size())
					{
						const SyringeDebugger::Hook* first = nullptr;

						size_t sz = 0;
						for(auto& hook : it.second.hooks)
						{
							if(hook.proc_address)
							{
								if(!first) {
									first = &hook;
								}

								sz += sizeof(code_call);
							}
						}

						if(sz && first)
						{
							sz += sizeof(jmp_back);

							//only use the information of the first working hook, however, every hook
							//should provide the same information to be secure
							sz += first->num_overridden;

							if(auto p_code_base = AllocMem(nullptr, sz))
							{
								BYTE* const base = p_code_base;
								BYTE* p_code = base;

								//Write Caller Code
								it.second.p_caller_code = std::move(p_code_base);
								for(const auto& hook : it.second.hooks)
								{
									if(hook.proc_address)
									{
										PatchMem(p_code, code_call, sizeof(code_call));	//code
										PatchMem(p_code + 0x03, &it.first, 4); //PUSH HookAddress

										const auto rel = RelativeOffset(p_code + 0x0D, hook.proc_address);
										PatchMem(p_code + 0x09, &rel, 4); //CALL
										PatchMem(p_code + 0x11, &pdReturnEIP, 4); //MOV
										PatchMem(p_code + 0x19, &pdReturnEIP, 4); //CMP
										PatchMem(p_code + 0x22, &pdReturnEIP, 4); //JMP ds:ReturnEIP

										p_code += sizeof(code_call);
									}
								}
								
								//Write overridden bytes
								//only use the information of the first working hook, however, every hook
								//should provide the same information to be secure
								if(auto const overridden = first->num_overridden)
								{
									over.resize(overridden);
									ReadMem(it.first, over.data(), overridden);
									PatchMem(p_code, over.data(), overridden);

									p_code += overridden;
								}

								//Write the jump back
								const auto rel = RelativeOffset(p_code + 0x05, static_cast<BYTE*>(it.first) + 0x05);
								PatchMem(p_code, jmp_back, sizeof(jmp_back));
								PatchMem(p_code + 0x01, &rel, 4);

								//Dump
								/*
								Log::WriteLine("Call dump for 0x%08X at 0x%08X:", it.first, base);

								char dump_str[0x200] = "\0";
								char buffer[0x10] = "\0";
								BYTE* dump = new BYTE[sz];

								ReadMem(it.second.p_caller_code, dump, sz);

								strcat(dump_str, "\t\t");
								for(unsigned int i = 0; i < sz; i++)
								{
									sprintf(buffer, "%02X ", dump[i]);
									strcat(dump_str, buffer);
								}

								Log::WriteLine(dump_str);
								Log::WriteLine();

								delete dump;*/

								//Patch original code
								BYTE* p_original_code = static_cast<BYTE*>(it.first);

								const auto rel2 = RelativeOffset(p_original_code + 5, base);
								PatchMem(p_original_code, jmp, sizeof(jmp));
								PatchMem(p_original_code + 0x01, &rel2, 4);

								//write NOPs
								//only use the information of the first working hook, however, every hook
								//should provide the same information to be secure
								BYTE buffer = NOP;
								for(size_t i = 5; i < first->num_overridden; ++i) {
									PatchMem(&p_original_code[i], &buffer, 1);
								}
							}
						}
					}
				}

				bHooksCreated = true;
			}

			//Restore
			PatchMem(exceptAddr, &bpMap[exceptAddr].original_opcode, 1);

			//single step mode
			context.EFlags |= 0x100;
			--context.Eip;

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		} 
		else
		{
			//could be a Debugger class breakpoint to call a patching function!

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			return DBG_EXCEPTION_NOT_HANDLED;
		}
	}
	else if(exceptCode == EXCEPTION_SINGLE_STEP)
	{
		BYTE buffer = INT3;
		const auto& threadInfo = threadInfoMap[dbgEvent.dwThreadId];
		PatchMem(threadInfo.lastBP, &buffer, 1);

		HANDLE hThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);

		context.EFlags &= ~0x100;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(hThread, &context);

		return DBG_CONTINUE;
	}
	else
	{
		Log::WriteLine("SyringeDebugger::HandleException: Exception (Code: 0x%08X at 0x%08X)!", exceptCode, exceptAddr);

		if(!bAVLogged)
		{
			//Log::WriteLine("SyringeDebugger::HandleException: ACCESS VIOLATION at 0x%08X!",exceptAddr);
			const auto& threadInfo = threadInfoMap[dbgEvent.dwThreadId];
			HANDLE currentThread = threadInfo.Thread;
			CONTEXT context;

			const char* access = nullptr;
			switch(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
			{
			case 0: access = "read from"; break;
			case 1: access = "write to"; break;
			case 8: access = "execute"; break;
			}

			Log::WriteLine("\tThe process tried to %s 0x%08X.",
				access,
				dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);

			context.ContextFlags = CONTEXT_FULL;
			GetThreadContext(currentThread, &context);

			Log::WriteLine();
			Log::WriteLine("Registers:");
			Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
				context.Eax, context.Ecx, context.Edx);
			Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
				context.Ebx, context.Esp, context.Ebp);
			Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
				context.Esi, context.Edi, context.Eip);
			Log::WriteLine();

			Log::WriteLine("\tStack dump:");
			auto esp = reinterpret_cast<DWORD*>(context.Esp);
			for(int i = 0; i < 100; i++)
			{
				DWORD* p = esp + i;

				DWORD dw;
				if(ReadMem(p, &dw, 4))
					Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
				else
					Log::WriteLine("\t0x%08X:\t(could not be read)", p);
			}
			Log::WriteLine();

#if 0
			Log::WriteLine("Making crash dump:\n");
			MINIDUMP_EXCEPTION_INFORMATION expParam;
			expParam.ThreadId = dbgEvent.dwThreadId;
			EXCEPTION_POINTERS ep;
			ep.ExceptionRecord = const_cast<PEXCEPTION_RECORD>(&dbgEvent.u.Exception.ExceptionRecord);
			ep.ContextRecord = &context;
			expParam.ExceptionPointers = &ep;
			expParam.ClientPointers = FALSE;

			wchar_t filename[MAX_PATH];
			wchar_t path[MAX_PATH];
			SYSTEMTIME time;

			GetLocalTime(&time);
			GetCurrentDirectoryW(MAX_PATH, path);

			swprintf(filename, MAX_PATH, L"%s\\syringe.crashed.%04u%02u%02u-%02u%02u%02u.dmp",
				path, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

			HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);

			MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

			MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, nullptr, nullptr);
			CloseHandle(dumpFile); 
				
			Log::WriteLine("Crash dump generated.\n");
#endif

			bAVLogged = true;
		}

		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}

bool SyringeDebugger::Run(char* params)
{
	if(!bControlLoaded || exe.empty()) {
		return false;
	}

	Log::WriteLine("SyringeDebugger::Run: Running process to debug. cmd = \"%s %s\"", exe.c_str(), params);

	if(!DebugProcess(exe.c_str(), params)) {
		return false;
	}

	Log::WriteLine("SyringeDebugger::Run: Allocating 0x1000 bytes ...");
	pAlloc = AllocMem(nullptr, 0x1000);

	Log::WriteLine("SyringeDebugger::Run: pAlloc = 0x%08X", static_cast<void*>(pAlloc));

	if(!pAlloc) {
		return false;
	}

	Log::WriteLine("SyringeDebugger::Run: Filling allocated space with zero...");
	char zero[0x1000] = "\0";
	PatchMem(pAlloc, zero, 0x1000);

	Log::WriteLine("SyringeDebugger::Run: Setting addresses...");

	//set addresses
	pdData = pAlloc + 0x100;

	pdProcAddress = pdData;
	pdMessage = pdData + 0x04;
	pdReturnEIP = pdData + 0x08;
	pdRegisters = pdData + 0x0C;
	pdBuffer = pdData + 0x34;

	//only needed at start
	pdLibName = pdData + 4;
	pdProcName = pdData + 4 + MaxNameLength;

	Log::WriteLine("SyringeDebugger::Run: Writing DLL loader & caller code...");

	//write DLL loader code
	pcLoadLibraryEnd = pAlloc;
	pcLoadLibrary = pAlloc + 1;

	static const BYTE cLoadLibrary[] = {
		0x90, // NOP
		0x50, // push eax
		0x51, // push ecx
		0x52, // push edx
		0x68, INIT, INIT, INIT, INIT, //push offset pdLibName
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pImLoadLibrary
		0x85, 0xC0, // test eax, eax
		0x74, 0x15, //jnz
		0x68, INIT, INIT, INIT, INIT, // push offset pdProcName
		0x50, // push eax
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pdImGetProcAddress
		0x85, 0xC0, // test eax, eax
		0x90, 0x90, // nop nop
		0xA3, INIT, INIT, INIT, INIT, // mov pdProcAddress, eax
		0x5A, // pop edx
		0x59, // pop ecx
		0x58, // pop eax
		0xEB, 0xD3 // jmp @0
	};

	PatchMem(pcLoadLibraryEnd, cLoadLibrary, sizeof(cLoadLibrary));
	PatchMem(pcLoadLibraryEnd + 0x05, &pdLibName, 4);
	PatchMem(pcLoadLibraryEnd + 0x0B, &pImLoadLibrary, 4);
	PatchMem(pcLoadLibraryEnd + 0x14, &pdProcName, 4);
	PatchMem(pcLoadLibraryEnd + 0x1B, &pImGetProcAddress, 4);
	PatchMem(pcLoadLibraryEnd + 0x24, &pdProcAddress, 4);

	Log::WriteLine("SyringeDebugger::Run: pcLoadLibrary = 0x%08X", pcLoadLibrary);

	//breakpoints for DLL loading and proc address retrieving
	bDLLsLoaded = false;
	bHooksCreated = false;
	loop_LoadLibrary = v_AllHooks.end();

	bpMap[pcEntryPoint].original_opcode = 0x00;
	bpMap[pcLoadLibraryEnd].original_opcode = 0x00;

	//set breakpoints
	SetBP(pcEntryPoint);
	SetBP(pcLoadLibraryEnd);

	DEBUG_EVENT dbgEvent;
	ResumeThread(pInfo.hThread);

	bAVLogged = false;

	Log::WriteLine("SyringeDebugger::Run: Entering debug loop...");

	for(;;)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		DWORD continueStatus = DBG_CONTINUE;
		bool wasBP = false;

		switch(dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			pInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
			pInfo.dwThreadId = dbgEvent.dwProcessId;
			pInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
			pInfo.dwThreadId = dbgEvent.dwThreadId;
			threadInfoMap[dbgEvent.dwThreadId].Thread = ThreadHandle(dbgEvent.u.CreateProcessInfo.hThread);
			threadInfoMap[dbgEvent.dwThreadId].lastBP = nullptr;
			CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			threadInfoMap[dbgEvent.dwThreadId].Thread = ThreadHandle(dbgEvent.u.CreateThread.hThread);
			threadInfoMap[dbgEvent.dwThreadId].lastBP = nullptr;
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			threadInfoMap[dbgEvent.dwThreadId].Thread.release();
			threadInfoMap.erase(dbgEvent.dwThreadId);
			break;

		case EXCEPTION_DEBUG_EVENT:
			continueStatus = HandleException(dbgEvent);
			wasBP = (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(dbgEvent.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		if(dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
			break;

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
	}

	CloseHandle(pInfo.hProcess);

	Log::WriteLine("SyringeDebugger::Run: Done.");
	Log::WriteLine();

	return true;
}

void SyringeDebugger::RemoveBP(LPVOID address, bool restoreOpcode)
{
	auto i = bpMap.find(address);
	if(i != bpMap.end())
	{
		if(restoreOpcode) {
			PatchMem(address, &i->second.original_opcode, 1);
		}

		bpMap.erase(i);
	}
}

bool SyringeDebugger::RetrieveInfo(std::string filename)
{
	bControlLoaded = false;

	exe = std::move(filename);

	Log::WriteLine("SyringeDebugger::RetrieveInfo: Retrieving info from the executable file...");

	PortableExecutable pe(exe);
	if(pe.IsValid())
	{
		DWORD dwImageBase = pe.GetImageBase();

		//Creation time stamp
		dwTimeStamp = pe.GetPEHeader().FileHeader.TimeDateStamp;

		//Entry point
		pcEntryPoint = reinterpret_cast<void*>(dwImageBase + pe.GetPEHeader().OptionalHeader.AddressOfEntryPoint);

		//Get Imports
		pImLoadLibrary = nullptr;
		pImGetProcAddress = nullptr;

		for(const auto& import : pe.GetImports()) {
			if(_strcmpi(import.Name.c_str(), "KERNEL32.DLL") == 0) {
				for(const auto& thunk : import.vecThunkData) {
					if(_strcmpi(thunk.Name.c_str(), "GETPROCADDRESS") == 0) {
						pImGetProcAddress = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					} else if(_strcmpi(thunk.Name.c_str(), "LOADLIBRARYA") == 0) {
						pImLoadLibrary = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					}
				}
			}
		}

		if(!pImGetProcAddress || !pImLoadLibrary) {
			Log::WriteLine("SyringeDebugger::RetrieveInfo: ERROR: Either a LoadLibraryA or a GetProcAddress import could not be found!");
			return false;
		}
	} else {
		Log::WriteLine("SyringeDebugger::RetrieveInfo: Failed to open the executable!");
		return false;
	}

	// read meta information: size and checksum
	if(ifstream is{ exe, ifstream::binary }) {
		is.seekg(0, ifstream::end);
		dwExeSize = static_cast<DWORD>(is.tellg());
		is.seekg(0, ifstream::beg);

		CRC32 crc;
		char buffer[0x1000];
		while(auto const read = is.read(buffer, std::size(buffer)).gcount()) {
			crc.compute(buffer, read);
		}
		dwExeCRC = crc.value();
	}

	Log::WriteLine("SyringeDebugger::RetrieveInfo: Executable information successfully retrieved.");
	Log::WriteLine("\texe = %s", exe.c_str());
	Log::WriteLine("\tpImLoadLibrary = 0x%08X", pImLoadLibrary);
	Log::WriteLine("\tpImGetProcAddress = 0x%08X", pImGetProcAddress);
	Log::WriteLine("\tpcEntryPoint = 0x%08X", pcEntryPoint);
	Log::WriteLine("\tdwExeSize = 0x%08X", dwExeSize);
	Log::WriteLine("\tdwExeCRC = 0x%08X", dwExeCRC);
	Log::WriteLine("\tdwTimestamp = 0x%08X", dwTimeStamp);
	Log::WriteLine();

	Log::WriteLine("SyringeDebugger::RetrieveInfo: Opening %s to determine imports.", exe.c_str());

	bControlLoaded = true;
	return true;
}

void SyringeDebugger::FindDLLs()
{
	bpMap.clear();

	if(bControlLoaded) {
		for(auto file = FindFile("*.dll"); file; ++file) {
			std::string fn(file->cFileName);

			//Log::WriteLine(__FUNCTION__ ": Potential DLL: \"%s\"", fn.c_str());

			PortableExecutable DLL(fn);
			if(DLL.IsValid()) {
				HookBuffer buffer;

				bool canLoad = false;
				if(auto hooks = DLL.FindSection(".syhks00")) {
					canLoad = ParseHooksSection(DLL, *hooks, buffer);
				} else {
					canLoad = ParseInjFileHooks(fn, buffer);
				}

				if(canLoad) {
					Log::WriteLine(__FUNCTION__ ": Recognized DLL: \"%s\"", fn.c_str());

					if(Handshake(DLL.GetFilename(), static_cast<int>(buffer.count), buffer.checksum.value(), canLoad)) {
						// canLoad has been updated already
					} else if(auto hosts = DLL.FindSection(".syexe00")) {
						canLoad = CanHostDLL(DLL, *hosts);
					}
				}

				if(canLoad) {
					for(const auto& it : buffer.hooks)
					{
						void* eip = it.first;
						auto &h = bpMap[eip];
						h.p_caller_code.clear();
						h.original_opcode = 0x00;
						h.hooks.insert(h.hooks.end(), it.second.begin(), it.second.end());
					}
				} else if(!buffer.hooks.empty()) {
					Log::WriteLine(__FUNCTION__ ": DLL load was prevented: \"%s\"", fn.c_str());
				}

			//} else {
			//	Log::WriteLine(__FUNCTION__ ": DLL Parse failed: \"%s\"", fn.c_str());
			}
		}

		// summarize all hooks
		v_AllHooks.clear();
		for(auto& it : bpMap) {
			for(auto& i : it.second.hooks) {
				v_AllHooks.push_back(&i);
			}
		}

		Log::WriteLine("SyringeDebugger::FindDLLs: Done (%d hooks added).", v_AllHooks.size());
		Log::WriteLine();
	}
}

bool SyringeDebugger::ParseInjFileHooks(const std::string &lib, HookBuffer &hooks) {
	std::string inj = lib + ".inj";

	if(auto F = FileHandle(_fsopen(inj.c_str(), "r", _SH_DENYWR))) {
		char line[0x100] = "\0";
		while(fgets(line, 0x100, F)) {
			if(*line != ';' && *line != '\r' && *line != '\n') {
				void* eip = nullptr;
				char func[MaxNameLength];
				size_t n_over = 0;

				// parse the line (length is optional, defaults to 0)
				if(sscanf_s(line, "%p = %[^ \t;,\r\n] , %x", &eip, func, MaxNameLength, &n_over) > 2) {
					hooks.add(eip, lib.c_str(), func, n_over);
				}
			}
		}

		return true;
	}

	return false;
}

bool SyringeDebugger::CanHostDLL(const PortableExecutable &DLL, const IMAGE_SECTION_HEADER &hosts) const {
	const auto hostSz = sizeof(hostdecl);
	auto hostCount = hosts.SizeOfRawData / hostSz;
	auto hostsPtr = hosts.PointerToRawData;
	std::string hostName;
	for(decltype(hostCount) ix = 0; ix < hostCount; ++ix) {
		hostdecl h;
		if(DLL.ReadBytes(hostsPtr, hostSz, reinterpret_cast<void *>(&h))) {
			hostsPtr += hostSz;
			if(h.hostNamePtr) {
				auto rawHostNamePtr = DLL.VirtualToRaw(h.hostNamePtr - DLL.GetImageBase());
				if(DLL.ReadCString(rawHostNamePtr, hostName)) {
					hostName += ".exe";
					if(!_strcmpi(hostName.c_str(), exe.c_str())) {
						return true;
					}
				}

			} else {
				break;
			}
		} else {
			break;
		}
	}
	return false;
}

bool SyringeDebugger::ParseHooksSection(const PortableExecutable &DLL, const IMAGE_SECTION_HEADER &hooks, HookBuffer &buffer) {
	const auto Sz = sizeof(hookdecl);
	auto Count = hooks.SizeOfRawData / Sz;
	auto Ptr = hooks.PointerToRawData;

	std::string hookName;
	for(decltype(Count) ix = 0; ix < Count; ++ix) {
		hookdecl h;
		if(DLL.ReadBytes(Ptr, Sz, reinterpret_cast<void *>(&h))) {
			Ptr += Sz;
			if(h.hookNamePtr) {
				auto rawHookNamePtr = DLL.VirtualToRaw(h.hookNamePtr - DLL.GetImageBase());
				if(DLL.ReadCString(rawHookNamePtr, hookName)) {
					auto eip = reinterpret_cast<void *>(h.hookAddr);
					buffer.add(eip, DLL.GetFilename(), hookName.c_str(), h.hookSize);
				}
				// else - msvc linker inserts arbitrary padding between variables that come from different .cpps
			}
		} else {
			Log::WriteLine(__FUNCTION__ ": Bytes read failed");
			return false;
		}
	}

	return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.
bool SyringeDebugger::Handshake(
	const char* const lib, int const hooks, unsigned int const crc, bool& outOk)
{
	if(auto const hLib = ModuleHandle(LoadLibrary(lib)))
	{
		if(auto const hProc = GetProcAddress(hLib, "SyringeHandshake"))
		{
			Log::WriteLine("SyringeDebugger::Handshake: Calling \"%s\" ...", lib);
			std::vector<char> buffer(0x101); // one more than we tell the dll

			auto const shInfo = std::make_unique<SyringeHandshakeInfo>();
			memset(shInfo.get(), 0, sizeof(SyringeHandshakeInfo));
			shInfo->cbSize = sizeof(SyringeHandshakeInfo);
			shInfo->num_hooks = hooks;
			shInfo->checksum = crc;
			shInfo->exeFilesize = dwExeSize;
			shInfo->exeCRC = dwExeCRC;
			shInfo->exeTimestamp = dwTimeStamp;
			shInfo->Message = buffer.data();
			shInfo->cchMessage = static_cast<int>(buffer.size()) - 1;

			auto const func = reinterpret_cast<SYRINGEHANDSHAKEFUNC>(hProc);
			auto const res = func(shInfo.get());

			if(SUCCEEDED(res))
			{
				buffer.back() = 0;
				Log::WriteLine("SyringeDebugger::Handshake: Answers \"%s\" (%X)", buffer.data(), res);
				outOk = (res == S_OK);
			}
			else
			{
				// don't use any properties of shInfo.
				Log::WriteLine("SyringeDebugger::Handshake: Failed (%X)", res);
				outOk = false;
			}

			return true;
		} else {
			//Log::WriteLine("SyringeDebugger::Handshake: Not available.");
		}
	}

	return false;
}
