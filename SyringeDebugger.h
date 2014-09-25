#pragma once
#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <windows.h>
#include "PortableExecutable.h"
#include <iostream>
#include <map>
#include <hash_map>
#include "CRC32.h"

#define	MAX_NAME_LENGTH	0x100
#define EXE_NAME_LENGTH	0x100

#define INIT 0x00

static const BYTE INT3 = 0xCC;	//trap to debugger interupt opcode.
									//was some static const w/e shit, caused errors =S   -pd
static const BYTE NOP = 0x90;

class SyringeDebugger
{
public:
	SyringeDebugger() :
		bAttached(false),
		bEntryBP(true),
		pcEntryPoint(nullptr),
		pcLoadLibrary(nullptr),
		pcLoadLibraryEnd(nullptr),
		pImLoadLibrary(nullptr),
		pImGetProcAddress(nullptr),
		bControlLoaded(false),
		bDLLsLoaded(false),
		pLastBP(nullptr)
	{}

	//Debugger
	bool DebugProcess(const char* exeFile, char* params);
	bool Run(char* params);
	DWORD HandleException(const DEBUG_EVENT& dbgEvent);

	//Breakpoints
	bool SetBP(void* address);
	void RemoveBP(void* address, bool restoreOpcode);

	//Memory
	VirtualMemoryHandle AllocMem(void* address, size_t size);
	bool PatchMem(void* address, void* buffer, DWORD size);
	bool ReadMem(void* address, void* buffer, DWORD size);

	//Syringe
	bool RetrieveInfo(std::string filename);
	void FindDLLs();

private:
	//Helper Functions
	DWORD RelativeOffset(DWORD from, DWORD to);

	//ThreadInfo
	struct threadInfo
	{
		ThreadHandle Thread;
		LPVOID lastBP;
	};
	std::map<DWORD, threadInfo> threadInfoMap;

	//ProcessInfo
	PROCESS_INFORMATION pInfo;

	//Flags
	bool bAttached;
	bool bEntryBP;
	void* pEntryBP;

	//Breakpoints
	struct Hook
	{
		char lib[MAX_NAME_LENGTH];
		char proc[MAX_NAME_LENGTH];
		void* proc_address;

		int num_overridden;
		//BYTE*		p_caller_code;
	};
	struct BPInfo
	{
		BYTE original_opcode;
		std::vector<Hook> hooks;
		VirtualMemoryHandle p_caller_code;
	};
	std::map<void*, BPInfo> bpMap;

	std::vector<Hook*> v_AllHooks;
	std::vector<Hook*>::iterator loop_LoadLibrary;

	//Syringe
	std::string exe;
	void* pcEntryPoint;
	void* pImLoadLibrary;
	void* pImGetProcAddress;
	VirtualMemoryHandle pAlloc;
	DWORD dwTimeStamp;
	DWORD dwExeSize;
	DWORD dwExeCRC;

	bool bControlLoaded;
	bool bDLLsLoaded;
	bool bHooksCreated;

	void* pLastBP;

	bool bAVLogged;

	//data addresses
	BYTE* pdData;

	void* pdProcAddress;
	void* pdMessage;
	void* pdReturnEIP;
	void* pdRegisters;
	void* pdBuffer;

	void* pdLibName;
	void* pdProcName;

	//Code addresses
	BYTE* pcLoadLibrary;
	BYTE* pcLoadLibraryEnd;

	struct HookBuffer {
		std::map<void*, std::vector<Hook>> hooks;
		CRC32 checksum;
		size_t count;

		HookBuffer() : count(0) {}

		void add(void* eip, Hook &hook) {
			auto &h = hooks[eip];
			h.push_back(hook);

			checksum.compute(&eip, sizeof(eip));
			checksum.compute(&hook.num_overridden, sizeof(hook.num_overridden));
			count++;
		}

		void add(void* eip, const char* filename, const char* proc, int num_overridden) {
			Hook hook;
			strncpy_s(hook.lib, filename, MAX_NAME_LENGTH - 1);
			strncpy_s(hook.proc, proc, MAX_NAME_LENGTH - 1);
			hook.proc_address = nullptr;
			hook.num_overridden = num_overridden;

			add(eip, hook);
		}
	};

	bool ParseInjFileHooks(const std::string &lib, HookBuffer &hooks);
	bool CanHostDLL(const PortableExecutable &DLL, const IMAGE_SECTION_HEADER &hosts) const;
	bool ParseHooksSection(const PortableExecutable &DLL, const IMAGE_SECTION_HEADER &hooks, HookBuffer &buffer);
	bool Handshake(const char* lib, int hooks, unsigned int crc, bool &outOk);
};

#pragma pack(push, 16)

__declspec(align(16)) struct hookdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
};

__declspec(align(16)) struct hostdecl {
	unsigned int hostChecksum;
	DWORD hostNamePtr;
};

#pragma pack(pop)

struct SyringeHandshakeInfo
{
	int cbSize;
	int num_hooks;
	unsigned int checksum;
	DWORD exeFilesize;
	DWORD exeTimestamp;
	unsigned int exeCRC;
	int cchMessage;
	char* Message;
};

using SYRINGEHANDSHAKEFUNC = HRESULT(__cdecl *)(SyringeHandshakeInfo*);
