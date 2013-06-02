#pragma warning(disable: 4786)	/*That "warning" annoyed me...
								  I recommend using this if you use std::map -pd*/
#pragma warning(disable: 4996)	//unsafe blahblah

#include "SyringeDebugger.h"
#include "Log.h"
#include "CRC32.h"

#include <fstream>
#include <DbgHelp.h>

using namespace std;

SyringeDebugger::SyringeDebugger()
{
	//bpMap=new BPMapType;
	threadInfoMap=new ThreadMapType;

	bAttached=false;
	bEntryBP=true;

	pcEntryPoint=NULL;
	pcLoadLibrary=NULL;
	pcLoadLibraryEnd=NULL;

	pImLoadLibrary=0;
	pImGetProcAddress=0;
	pAlloc=NULL;
	*exe=0;

	bControlLoaded=false;
	bDLLsLoaded=false;
	v_AllHooks.clear();
	pLastBP=NULL;
}

SyringeDebugger::~SyringeDebugger()
{
	//delete bpMap;
	ThreadMapType::iterator i;
	for(i = threadInfoMap->begin(); i != threadInfoMap->end(); ++i)
		CloseHandle(i->second.hThread);
	delete threadInfoMap;
}

bool SyringeDebugger::DebugProcess(const char* exeFile,char* params)
{
	STARTUPINFO startupInfo;

	memset(&startupInfo, 0, sizeof(startupInfo));
	startupInfo.cb=sizeof(startupInfo);

	bool retVal=(CreateProcess(
		exeFile,params,NULL,NULL,false, 
		DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED, 
		NULL,NULL,&startupInfo,&pInfo)!=0);

	bAttached = retVal;
	return retVal;
}

bool SyringeDebugger::PatchMem(void* address,void* buffer,DWORD size)
{
	return (WriteProcessMemory(pInfo.hProcess,address,buffer,size,NULL)==TRUE);
}

bool SyringeDebugger::ReadMem(void* address,void* buffer,DWORD size)
{
	DWORD read;
	ReadProcessMemory(pInfo.hProcess,address,buffer,size,&read);
	return (read==size);
}

LPVOID SyringeDebugger::AllocMem(void* address,size_t size)
{
	return VirtualAllocEx(pInfo.hProcess,address,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
}

bool SyringeDebugger::SetBP(void* address)
{
	//save overwritten code and set INT 3
	if(bpMap[address].original_opcode==0x00)
	{
		ReadMem(address,&bpMap[address].original_opcode,1);
		return PatchMem(address,(LPVOID)&INT3,1);
	}
	return true;
}

DWORD SyringeDebugger::RelativeOffset(DWORD from,DWORD to)
{
	if(from == to)
		return 0;
	else if(from < to)
		return to - from;
	else //if(pos > dest)
		return ~(from - to) + 1;
}

DWORD SyringeDebugger::HandleException(const DEBUG_EVENT& dbgEvent)
{
	DWORD exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	if (exceptCode == EXCEPTION_BREAKPOINT)
	{
		HANDLE currentThread=(*threadInfoMap)[dbgEvent.dwThreadId].hThread;
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
			context.EFlags &= ~0x100;
			PatchMem((*threadInfoMap)[dbgEvent.dwThreadId].lastBP, (LPVOID)&INT3, 1);
		}

		//Load DLLs and retrieve proc addresses
		if(!bDLLsLoaded) //&& (exceptAddr==pcEntryPoint || exceptAddr==pcLoadLibraryEnd))
		{
			//Restore
			PatchMem(exceptAddr,(void*)&bpMap[exceptAddr].original_opcode, 1);

			bool doPatch = true;
			if(loop_LoadLibrary == v_AllHooks.end())
				loop_LoadLibrary = v_AllHooks.begin();
			else
			{
				ReadMem(pdProcAddress, &(*loop_LoadLibrary)->proc_address, 4);

				if((*loop_LoadLibrary)->proc_address) {
					Log::SelWriteLine(
						"SyringeDebugger::HandleException: Loaded ProcAddress: %s - %s - 0x%08X",
						(*loop_LoadLibrary)->lib,
						(*loop_LoadLibrary)->proc,
						(*loop_LoadLibrary)->proc_address);
				} else {
					doPatch = false;
					Log::SelWriteLine(
							"SyringeDebugger::HandleException: Could not retrieve ProcAddress for: %s - %s",
							(*loop_LoadLibrary)->lib,
							(*loop_LoadLibrary)->proc);
				}

				++loop_LoadLibrary;
			}

			if(loop_LoadLibrary != v_AllHooks.end())
			{
//				if(doPatch) {
					PatchMem(pdLibName, &(*loop_LoadLibrary)->lib, MAX_NAME_LENGTH);
					PatchMem(pdProcName, &(*loop_LoadLibrary)->proc, MAX_NAME_LENGTH);
//				}
				
				context.Eip = (DWORD)pcLoadLibrary;

				//single step mode
				context.EFlags |= 0x100;
				context.ContextFlags = CONTEXT_CONTROL;
				SetThreadContext(currentThread, &context);

				(*threadInfoMap)[dbgEvent.dwThreadId].lastBP = exceptAddr;

				return DBG_CONTINUE;
			}
			else
			{
				Log::SelWriteLine("SyringeDebugger::HandleException: Finished retrieving proc addresses.");
				bDLLsLoaded=true;

				context.Eip=(DWORD)pcEntryPoint;

				//single step mode
				context.EFlags |= 0x100;
				context.ContextFlags = CONTEXT_CONTROL;
				SetThreadContext(currentThread, &context);

				(*threadInfoMap)[dbgEvent.dwThreadId].lastBP = exceptAddr;

				return DBG_CONTINUE;
			}
		}

		if(exceptAddr == pcEntryPoint)
		{
			if(!bHooksCreated)
			{
				Log::SelWriteLine("SyringeDebugger::HandleException: Creating code hooks.");

				BYTE code_call[] =
				{
					0x60,0x9C, //PUSHAD, PUSHFD
					0x68,INIT,INIT,INIT,INIT, //PUSH HookAddress
					0x54, //PUSH ESP
					0xE8,INIT,INIT,INIT,INIT, //CALL ProcAddress
					0x83,0xC4,0x08, //ADD ESP, 8
					0xA3,INIT,INIT,INIT,INIT, //MOV ds:ReturnEIP, EAX
					0x9D,0x61, //POPFD, POPAD
					0x83,0x3D,INIT,INIT,INIT,INIT,0x00, //CMP ds:ReturnEIP, 0
					0x74,0x06, //JZ .proceed
					0xFF,0x25,INIT,INIT,INIT,INIT, //JMP ds:ReturnEIP
				};

				BYTE jmp_back[] = {0xE9,INIT,INIT,INIT,INIT,};
				BYTE jmp[] = {0xE9,INIT,INIT,INIT,INIT,};

				for(BPMapType::iterator it = bpMap.begin(); it != bpMap.end(); it++)
				{
					if(it->first && it->first != pcEntryPoint && it->second.hooks.size())
					{
						int first = -1;

						size_t sz = 0;
						for(size_t i = 0; i < it->second.hooks.size(); i++)
						{
							if(it->second.hooks[i].proc_address)
							{
								if(first < 0)
									first = i;

								sz += sizeof(code_call);
							}
						}

						if(sz && first >= 0)
						{
							sz += sizeof(jmp_back);

							//only use the information of the first working hook, however, every hook
							//should provide the same information to be secure
							sz += it->second.hooks[first].num_overridden;

							BYTE* p_code_base = (BYTE*)AllocMem(NULL,sz);
							BYTE* p_code = p_code_base;

							if(p_code_base)
							{
								DWORD rel;

								//Write Caller Code
								it->second.p_caller_code = p_code_base;
								for(size_t i = 0; i < it->second.hooks.size(); i++)
								{
									if(it->second.hooks[i].proc_address)
									{
										//moved to the BP info
										//it->second.hooks[i].p_caller_code = p_code_base;

										PatchMem(p_code, code_call, sizeof(code_call));	//code
										PatchMem(p_code+0x03, &(void*)it->first, 4); //PUSH HookAddress
										
										rel = RelativeOffset((DWORD)p_code + 0x0D, (DWORD)it->second.hooks[i].proc_address);
										PatchMem(p_code+0x09, &rel, 4); //CALL
										PatchMem(p_code+0x11, &pdReturnEIP, 4); //MOV
										PatchMem(p_code+0x19, &pdReturnEIP, 4); //CMP
										PatchMem(p_code+0x22, &pdReturnEIP, 4); //JMP ds:ReturnEIP

										p_code += sizeof(code_call);
									}
								}
								
								//Write overridden bytes
								//only use the information of the first working hook, however, every hook
								//should provide the same information to be secure
								if(it->second.hooks[first].num_overridden > 0)
								{
									BYTE* over = new BYTE[it->second.hooks[first].num_overridden];
									ReadMem(it->first,over, it->second.hooks[first].num_overridden);
									PatchMem(p_code,over, it->second.hooks[first].num_overridden);
									delete over;

									p_code += it->second.hooks[first].num_overridden;
								}

								//Write the jump back
								rel = RelativeOffset((DWORD)p_code+0x05, (DWORD)it->first+0x05);
								PatchMem(p_code, jmp_back, sizeof(jmp_back));
								PatchMem(p_code + 0x01, &rel,4);

								//Dump
								/*
								Log::SelWriteLine("Call dump for 0x%08X at 0x%08X:", it->first, p_code_base);

								char dump_str[0x200] = "\0";
								char buffer[0x10] = "\0";
								BYTE* dump = new BYTE[sz];

								ReadMem(it->second.p_caller_code, dump, sz);

								strcat(dump_str, "\t\t");
								for(unsigned int i = 0; i < sz; i++)
								{
									sprintf(buffer, "%02X ", dump[i]);
									strcat(dump_str, buffer);
								}

								Log::SelWriteLine(dump_str);
								Log::SelWriteLine();

								delete dump;*/

								//Patch original code
								BYTE* p_original_code = (BYTE*)it->first;

								rel = RelativeOffset((DWORD)p_original_code + 5, (DWORD)p_code_base);
								PatchMem(p_original_code, jmp, sizeof(jmp));
								PatchMem(p_original_code + 0x01, &rel,4);

								//write NOPs
								//only use the information of the first working hook, however, every hook
								//should provide the same information to be secure
								int n_nop = it->second.hooks[first].num_overridden - 5;
								if(n_nop > 0)
								{
									for(int i = 0; i < n_nop; i++)
										PatchMem(p_original_code + 0x05 + i,(void*)&NOP,1);
								}
							}
						}
					}
				}

				bHooksCreated = true;
			}

			//Restore
			PatchMem(exceptAddr, (void*)&bpMap[exceptAddr].original_opcode, 1);

			//single step mode
			context.EFlags |= 0x100;
			--context.Eip;

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			(*threadInfoMap)[dbgEvent.dwThreadId].lastBP = exceptAddr;

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
		PatchMem((*threadInfoMap)[dbgEvent.dwThreadId].lastBP, (LPVOID)&INT3, 1);

		HANDLE hThread =( *threadInfoMap)[dbgEvent.dwThreadId].hThread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);

		context.EFlags &= ~0x100;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(hThread, &context);

		return DBG_CONTINUE;
	}
	else if (exceptCode == EXCEPTION_ACCESS_VIOLATION)
	{
		if(!bAVLogged)
		{
			Log::SelWriteLine("SyringeDebugger::HandleException: ACCESS VIOLATION at 0x%08X!",exceptAddr);
			
			HANDLE currentThread = (*threadInfoMap)[dbgEvent.dwThreadId].hThread;
			CONTEXT context;

			char buffer[0x20] = "\0";
			switch(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
			{
			case 0: strcpy(buffer, "read from");break;
			case 1: strcpy(buffer, "write to");break;
			case 8: strcpy(buffer, "execute");break;
			}

			Log::SelWriteLine("\tThe process tried to %s 0x%08X.",
				buffer,
				dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);

			context.ContextFlags = CONTEXT_FULL;
			GetThreadContext(currentThread, &context);

			Log::SelWriteLine();
			Log::SelWriteLine("Registers:");
			Log::SelWriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
				context.Eax, context.Ecx, context.Edx);
			Log::SelWriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
				context.Ebx, context.Esp, context.Ebp);
			Log::SelWriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
				context.Esi, context.Edi, context.Eip);
			Log::SelWriteLine();

			Log::SelWriteLine("\tStack dump:");
			DWORD* esp=(DWORD*)context.Esp;
			for(int i = 0; i < 100; i++)
			{
				DWORD* p = esp + i;

				DWORD dw;
				if(ReadMem(p, &dw, 4))
					Log::SelWriteLine("\t0x%08X:\t0x%08X", p, dw);
				else
					Log::SelWriteLine("\t0x%08X:\t(could not be read)", p);
			}
			Log::SelWriteLine();


			Log::SelWriteLine("Making crash dump:\n");
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
					FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

				MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

				MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, NULL, NULL);
				CloseHandle(dumpFile); 
				
				Log::SelWriteLine("Crash dump generated.\n");

			bAVLogged = true;
		}

		return DBG_EXCEPTION_NOT_HANDLED;
	}
	else 
	{
		Log::SelWriteLine("SyringeDebugger::HandleException: Exception (Code: 0x%08X at 0x%08X)!", exceptCode, exceptAddr);

		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}

bool SyringeDebugger::Run(char* params)
{
	if(!bControlLoaded || *exe == 0)
		return false;

	Log::SelWriteLine("SyringeDebugger::Run: Running process to debug. cmd = \"%s %s\"", exe, params);

	if(!DebugProcess(exe, params))
		return false;

	Log::SelWriteLine("SyringeDebugger::Run: Allocating 0x1000 bytes ...");
	pAlloc = (BYTE*)AllocMem(NULL, 0x1000);

	Log::SelWriteLine("SyringeDebugger::Run: pAlloc = 0x%08X",pAlloc);

	if(!pAlloc)return false;

	Log::SelWriteLine("SyringeDebugger::Run: Filling allocated space with zero...");
	char zero[0x1000] = "\0";
	PatchMem(pAlloc, zero, 0x1000);

	Log::SelWriteLine("SyringeDebugger::Run: Setting addresses...");

	//set addresses
	pdData=pAlloc + 0x100;

	pdProcAddress = pdData;
	pdMessage = pdData + 0x04;
	pdReturnEIP = pdData + 0x08;
	pdRegisters = pdData + 0x0C;
	pdBuffer = pdData + 0x34;

	//only needed at start
	pdLibName = pdData + 4;					
	pdProcName = pdData + 4 + MAX_NAME_LENGTH;

	Log::SelWriteLine("SyringeDebugger::Run: Writing DLL loader & caller code...");

	//write DLL loader code
	pcLoadLibraryEnd = pAlloc;
	pcLoadLibrary = pAlloc + 1;

	BYTE cLoadLibrary[] = {
		0x90, // NOP
		0x50, // push eax
		0x51, // push ecx
		0x52, // push edx
		0x68,INIT,INIT,INIT,INIT, //push offset pdLibName
		0xFF,0x15,INIT,INIT,INIT,INIT, // call pImLoadLibrary
		0x85,0xC0, // test eax, eax
		0x74,0x15, //jnz
		0x68,INIT,INIT,INIT,INIT, // push offset pdProcName
		0x50, // push eax
		0xFF,0x15,INIT,INIT,INIT,INIT, // call pdImGetProcAddress
		0x85,0xC0, // test eax, eax
		0x90,0x90, // nop nop
		0xA3,INIT,INIT,INIT,INIT, // mov pdProcAddress, eax
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

	Log::SelWriteLine("SyringeDebugger::Run: pcLoadLibrary = 0x%08X", pcLoadLibrary);

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

	Log::SelWriteLine("SyringeDebugger::Run: Entering debug loop...");

	while(true)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		DWORD continueStatus = DBG_CONTINUE;
		bool wasBP = false;

		switch (dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			pInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
			pInfo.dwThreadId = dbgEvent.dwProcessId;
			pInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
			pInfo.dwThreadId = dbgEvent.dwThreadId;
			(*threadInfoMap)[dbgEvent.dwThreadId].hThread = dbgEvent.u.CreateProcessInfo.hThread;
			(*threadInfoMap)[dbgEvent.dwThreadId].lastBP = NULL;
			CloseHandle(dbgEvent.u.CreateProcessInfo.hFile); 
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			(*threadInfoMap)[dbgEvent.dwThreadId].hThread = dbgEvent.u.CreateThread.hThread;
			(*threadInfoMap)[dbgEvent.dwThreadId].lastBP = NULL;
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			threadInfoMap->erase(dbgEvent.dwThreadId);
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

	Log::SelWriteLine("SyringeDebugger::Run: Done.");
	Log::SelWriteLine();

	return true;
}

void SyringeDebugger::RemoveBP(LPVOID address, bool restoreOpcode)
{
	BPMapType::iterator i = bpMap.find(address);
	if(i != bpMap.end())
	{
		if(restoreOpcode)
			PatchMem(address, (void*)&bpMap[address].original_opcode, 1);

		bpMap.erase(i);
	}
}

bool SyringeDebugger::RetrieveInfo(const char* filename)
{
	bControlLoaded = false;

	strncpy(exe, filename, EXE_NAME_LENGTH);

	Log::SelWriteLine("SyringeDebugger::RetrieveInfo: Retrieving info from the executable file...");

	PortableExecutable pe;
	if(pe.ReadFile(exe))
	{
		DWORD dwImageBase = pe.GetImageBase();

		//Creation time stamp
		dwTimeStamp = pe->GetPEHeader()->FileHeader.TimeDateStamp;

		//Entry point
		pcEntryPoint = (void*)(dwImageBase + pe.GetPEHeader()->OptionalHeader.AddressOfEntryPoint);

		//Get Imports
		pImLoadLibrary = NULL;
		pImGetProcAddress = NULL;

		std::vector<PEImport>* v = pe.GetImports();
		for(size_t i = 0; i < v->size(); i++) {
			if(_strcmpi(v->at(i).lpName, "KERNEL32.DLL") == 0) {
				std::vector<PEThunkData>* u = &v->at(i).vecThunkData;
				for(size_t k = 0; k < u->size(); k++) {
					if(_strcmpi(u->at(k).lpName, "GETPROCADDRESS") == 0) {
						pImGetProcAddress = (void*)(dwImageBase + u->at(k).Address);
					} else if(_strcmpi(u->at(k).lpName, "LOADLIBRARYA") == 0) {
						pImLoadLibrary =(void*)(dwImageBase + u->at(k).Address);
					}
				}
			}
		}

		if(!pImGetProcAddress || !pImLoadLibrary) {
			Log::SelWriteLine("SyringeDebugger::RetrieveInfo: ERROR: Either a LoadLibraryA or a GetProcAddress import could not be found!");
			return false;
		}
	} else {
		Log::SelWriteLine("SyringeDebugger::RetrieveInfo: Failed to open the executable!");
		return false;
	}

	// read meta information: size and checksum
	ifstream is;
	is.open(exe, ifstream::binary);
	is.seekg(0, ifstream::end);
	dwExeSize = static_cast<DWORD>(is.tellg());
	is.seekg(0, ifstream::beg);

	CRC32 crc;
	char buffer[0x1000];
	while(std::streamsize read = is.read(buffer, sizeof(buffer)).gcount()) {
		crc.compute(buffer, read);
	}	
	dwExeCRC =  crc.value();
	is.close();

	Log::SelWriteLine("SyringeDebugger::RetrieveInfo: Executable information successfully retrieved.");
	Log::SelWriteLine("\texe = %s", exe);
	Log::SelWriteLine("\tpImLoadLibrary = 0x%08X", pImLoadLibrary);
	Log::SelWriteLine("\tpImGetProcAddress = 0x%08X", pImGetProcAddress);
	Log::SelWriteLine("\tpcEntryPoint = 0x%08X", pcEntryPoint);
	Log::SelWriteLine("\tdwExeSize = 0x%08X", dwExeSize);
	Log::SelWriteLine("\tdwExeCRC = 0x%08X", dwExeCRC);
	Log::SelWriteLine("\tdwTimestamp = 0x%08X", dwTimeStamp);
	Log::SelWriteLine();

	Log::SelWriteLine("SyringeDebugger::RetrieveInfo: Opening %s to determine imports.", exe);

	bControlLoaded = true;
	return true;
}

void SyringeDebugger::FindDLLs()
{
	bpMap.clear();

	if(bControlLoaded) {
		WIN32_FIND_DATA find;
		HANDLE hFind = FindFirstFile("*.dll", &find);
		bool bFindMore = (hFind != INVALID_HANDLE_VALUE);

		while(bFindMore) {
			char fn[0x100] = "\0";
			strncpy(fn, find.cFileName, 0x100);

//			Log::SelWriteLine(__FUNCTION__ ": Potential DLL: \"%s\"", fn);

			PortableExecutable DLL;
			if(DLL.ReadFile(fn)) {
				DLL.OpenHandle();
				DWORD dwImageBase = DLL.GetImageBase();

				HookBuffer buffer;

				bool canLoad = false;
				if(auto hooks = DLL.FindSection(".syhks00")) {
					canLoad = ParseHooksSection(DLL, *hooks, buffer);
				} else {
					canLoad = ParseInjFileHooks(fn, buffer);
				}

				if(canLoad) {
					Log::SelWriteLine(__FUNCTION__ ": Recognized DLL: \"%s\"", fn);

					if(auto hosts = DLL.FindSection(".syexe00")) {
						canLoad = CanHostDLL(DLL, *hosts);
					}
				}

				if(canLoad) {
					for(HookBufferType::iterator it = buffer.hooks.begin(); it != buffer.hooks.end(); ++it)
					{
						void* eip = it->first;
						auto &h = bpMap[eip];
						h.p_caller_code = NULL;
						h.original_opcode = 0x00;

						for(std::vector<Hook>::iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2)
						{
							h.hooks.push_back(*it2);
						}
					}
				} else if(!buffer.hooks.empty()) {
					Log::SelWriteLine(__FUNCTION__ ": DLL load was prevented: \"%s\"", fn);
				}
				DLL.CloseHandle();

//			} else {
//				Log::SelWriteLine(__FUNCTION__ ": DLL Parse failed: \"%s\"", fn);
			}

			bFindMore = (FindNextFile(hFind, &find) != 0);
		}
		FindClose(hFind);

		// summarize all hooks
		v_AllHooks.clear();
		for(auto it = bpMap.begin(); it != bpMap.end(); it++) {
			auto &h = it->second.hooks;
			for(size_t i = 0; i < h.size(); i++) {
				v_AllHooks.push_back(&h[i]);
			}
		}

		Log::SelWriteLine("SyringeDebugger::FindDLLs: Done (%d hooks added).", v_AllHooks.size());
		Log::SelWriteLine();
	}
}

bool SyringeDebugger::ParseInjFileHooks(const char* fn, HookBuffer &hooks) {
	char fn_inj[0x100] = "\0";
	strcpy(fn_inj, fn);
	strcat(fn_inj, ".inj");

	char line[0x100] = "\0";
	if(FILE* F = fopen(fn_inj, "r")) {
		while(fgets(line, 0x100, F)) {
			if(*line != ';' && *line != '\r' && *line != '\n') {
				if(char* func = strchr(line, '=')) {
					*func++ = 0;

					char* over = strchr(func, ',');

					void* eip;
					int n_over = 0;

					sscanf(line, "%X", &eip);

					while(*func==' ' || *func=='\t') {
						++func;
					}

					func=strtok(func, " \t;,\r\n");

					if(over) {
						if(*++over) {
							sscanf(over, "%X", &n_over);
						}
					}

					hooks.add(eip, fn, func, n_over);
				}
			}
		}
		fclose(F);

		return true;
	}

	return false;
}

bool SyringeDebugger::CanHostDLL(const PortableExecutable &DLL, const IMAGE_SECTION_HEADER &hosts) const {
	auto hostSz = sizeof(hostdecl);
	auto hostCount = hosts.SizeOfRawData / hostSz;
	auto hostsPtr = hosts.PointerToRawData;
	for(decltype(hostCount) ix = 0; ix < hostCount; ++ix) {
		hostdecl h;
		if(DLL.ReadBytes(hostsPtr, hostSz, reinterpret_cast<void *>(&h))) {
			hostsPtr += hostSz;
			if(h.hostNamePtr) {
				auto rawHostNamePtr = DLL.VirtualToRaw(h.hostNamePtr - DLL.GetImageBase());
				std::string hostName;
				if(DLL.ReadCString(rawHostNamePtr, hostName)) {
					hostName += ".exe";
					if(!strcmpi(hostName.c_str(), exe)) {
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
	auto Sz = sizeof(hookdecl);
	auto Count = hooks.SizeOfRawData / Sz;
	auto Ptr = hooks.PointerToRawData;
	
	for(decltype(Count) ix = 0; ix < Count; ++ix) {
		hookdecl h;
		if(DLL.ReadBytes(Ptr, Sz, reinterpret_cast<void *>(&h))) {
			Ptr += Sz;
			if(h.hookNamePtr) {
				auto rawHookNamePtr = DLL.VirtualToRaw(h.hookNamePtr - DLL.GetImageBase());
				std::string hookName;
				if(DLL.ReadCString(rawHookNamePtr, hookName)) {
					auto eip = reinterpret_cast<void *>(h.hookAddr);
					buffer.add(eip, DLL.GetFilename(), hookName.c_str(), h.hookSize);
				}
				// else - msvc linker inserts arbitrary padding between variables that come from different .cpps
			}
		} else {
			Log::SelWriteLine(__FUNCTION__ ": Bytes read failed");
			return false;
		}
	}

	return true;
}