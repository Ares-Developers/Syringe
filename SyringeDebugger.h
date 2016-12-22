#pragma once
#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <windows.h>
#include "PortableExecutable.h"
#include <iostream>
#include <map>
#include "CRC32.h"

class SyringeDebugger
{
	static const size_t MaxNameLength = 0x100u;

	static const BYTE INIT = 0x00;
	static const BYTE INT3 = 0xCC;	//trap to debugger interupt opcode.
	static const BYTE NOP = 0x90;

public:
	SyringeDebugger() :
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
	bool DebugProcess(char const* arguments);
	bool Run(char const* arguments);
	DWORD HandleException(const DEBUG_EVENT& dbgEvent);

	//Breakpoints
	bool SetBP(void* address);
	void RemoveBP(LPVOID address, bool restoreOpcode);

	//Memory
	VirtualMemoryHandle AllocMem(void* address, size_t size);
	bool PatchMem(void* address, const void* buffer, DWORD size);
	bool ReadMem(const void* address, void* buffer, DWORD size);

	//Syringe
	bool RetrieveInfo(std::string filename);
	void FindDLLs();

private:
	//Helper Functions
	static DWORD __fastcall RelativeOffset(const void* from, const void* to);

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
	bool bEntryBP;
	void* pEntryBP;

	//Breakpoints
	struct Hook
	{
		char lib[MaxNameLength];
		char proc[MaxNameLength];
		void* proc_address;

		size_t num_overridden;
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
		size_t count{ 0 };

		void add(void* eip, Hook &hook) {
			auto &h = hooks[eip];
			h.push_back(hook);

			checksum.compute(&eip, sizeof(eip));
			checksum.compute(&hook.num_overridden, sizeof(hook.num_overridden));
			count++;
		}

		void add(void* eip, const char* filename, const char* proc, size_t num_overridden) {
			Hook hook;
			strncpy_s(hook.lib, filename, _TRUNCATE);
			strncpy_s(hook.proc, proc, _TRUNCATE);
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

struct alignas(16) hookdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
};

struct alignas(16) hostdecl {
	unsigned int hostChecksum;
	DWORD hostNamePtr;
};

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
