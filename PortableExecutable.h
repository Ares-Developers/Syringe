//A class to parse PE files
#pragma once

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include "Handle.h"
#include "Support.h"

#include <string>
#include <string_view>
#include <vector>

#include <windows.h>

struct PEThunkData
{
	IMAGE_THUNK_DATA			uThunkData;
	bool						bIsOrdinal;

	DWORD						Address;
	
	//bIsOrdinal
	int							Ordinal;
	
	//!bIsOrdinal
	std::string					Name;
	WORD						wWord;
};

struct PEImport
{
	IMAGE_IMPORT_DESCRIPTOR		uDesc;
	std::string					Name;

	std::vector<PEThunkData>	vecThunkData;
};

class PortableExecutable
{
private:
	std::string					Filename;

	//Basic PE structure;
	IMAGE_DOS_HEADER			uDOSHeader;
	IMAGE_NT_HEADERS			uPEHeader;

	//Sections
	std::vector<IMAGE_SECTION_HEADER>	vecPESections;

	//Imports
	std::vector<PEImport>		vecImports;

	FileHandle Handle;
	
public:
	PortableExecutable(std::string_view filename) : Filename(filename) {
		if(!Filename.empty()) {
			Handle = FileHandle(_fsopen(Filename.c_str(), "rb", _SH_DENYNO));
		}

		if(!this->ReadFile()) {
			throw_lasterror_or(ERROR_BAD_EXE_FORMAT, Filename);
		}
	};

	const char * GetFilename() const { return Filename.c_str(); }

	//PE
	const IMAGE_DOS_HEADER& GetDOSHeader() const { return uDOSHeader; }
	const IMAGE_NT_HEADERS& GetPEHeader() const { return uPEHeader; }

	//Sections
	const std::vector<IMAGE_SECTION_HEADER>& GetSections() { return vecPESections; }
	const std::vector<PEImport>& GetImports() { return vecImports; }

	//Helpers
	DWORD GetImageBase() const;

	DWORD VirtualToRaw(DWORD dwAddress) const;

	bool ReadBytes(DWORD dwRawAddress, size_t Size, void *Dest) const;

	bool ReadCString(DWORD dwRawAddress, std::string &result) const;

	IMAGE_SECTION_HEADER const* FindSection(std::string_view name) const noexcept;

private:
	bool ReadFile();
};
