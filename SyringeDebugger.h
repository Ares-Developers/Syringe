#pragma once
#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <windows.h>
#include "PortableExecutable.h"
#include <iostream>
#include <map>
#include <string_view>
#include "CRC32.h"

// returns something %.*s can format
inline auto printable(std::string_view const string) {
	return std::make_pair(string.size(), string.data());
}

class SyringeDebugger
{
	static const size_t MaxNameLength = 0x100u;

	static const BYTE INIT = 0x00;
	static const BYTE INT3 = 0xCC;	//trap to debugger interupt opcode.
	static const BYTE NOP = 0x90;

public:
	SyringeDebugger() = default;

	//Debugger
	bool DebugProcess(std::string_view arguments);
	bool Run(std::string_view arguments);
	DWORD HandleException(const DEBUG_EVENT& dbgEvent);

	//Breakpoints
	bool SetBP(void* address);
	void RemoveBP(LPVOID address, bool restoreOpcode);

	//Memory
	VirtualMemoryHandle AllocMem(void* address, size_t size);
	bool PatchMem(void* address, const void* buffer, DWORD size);
	bool ReadMem(const void* address, void* buffer, DWORD size);

	//Syringe
	bool RetrieveInfo(std::string_view filename);
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
	bool bEntryBP{ true };

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
	void* pcEntryPoint{ nullptr };
	void* pImLoadLibrary{ nullptr };
	void* pImGetProcAddress{ nullptr };
	VirtualMemoryHandle pAlloc;
	DWORD dwTimeStamp{ 0u };
	DWORD dwExeSize{ 0u };
	DWORD dwExeCRC{ 0u };

	bool bControlLoaded{ false };
	bool bDLLsLoaded{ false };
	bool bHooksCreated{ false };

	void* pLastBP{ nullptr };

	bool bAVLogged{ false };

	//data addresses
	BYTE* pdData{ nullptr };

	void* pdProcAddress{ nullptr };
	void* pdMessage{ nullptr };
	void* pdReturnEIP{ nullptr };
	void* pdRegisters{ nullptr };
	void* pdBuffer{ nullptr };

	void* pdLibName{ nullptr };
	void* pdProcName{ nullptr };

	//Code addresses
	BYTE* pcLoadLibrary{ nullptr };
	BYTE* pcLoadLibraryEnd{ nullptr };

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

		void add(
			void* const eip, std::string_view const filename,
			std::string_view const proc, size_t const num_overridden)
		{
			Hook hook;
			hook.lib[filename.copy(hook.lib, std::size(hook.lib) - 1)] = '\0';
			hook.proc[proc.copy(hook.proc, std::size(hook.proc) - 1)] = '\0';
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
