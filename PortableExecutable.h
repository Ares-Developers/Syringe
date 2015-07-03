//A class to parse PE files
#pragma once

#include "Handle.h"

#include <stdio.h>
#include <vector>
#include <string>
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
	PortableExecutable(std::string filename) : Filename(std::move(filename)) {
		if(!Filename.empty()) {
			Handle = FileHandle(_fsopen(Filename.c_str(), "rb", _SH_DENYNO));
		}

		this->ReadFile();
	};

	const char * GetFilename() const { return Filename.c_str(); }

	bool IsValid() const { return Handle != nullptr; }

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

	const IMAGE_SECTION_HEADER * FindSection(const char * findName) const;

private:
	bool ReadFile();
};
