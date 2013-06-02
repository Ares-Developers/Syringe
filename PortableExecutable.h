//A class to parse PE files

#ifndef PE_H
#define PE_H

#include <stdio.h>
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
	char*						lpName;
	WORD						wWord;
};

struct PEImport
{
	IMAGE_IMPORT_DESCRIPTOR		uDesc;
	char*						lpName;

	std::vector<PEThunkData>	vecThunkData;
};

class PortableExecutable
{
private:
	char*						lpFileName;

	//Basic PE structure;
	IMAGE_DOS_HEADER			uDOSHeader;
	IMAGE_NT_HEADERS			uPEHeader;

	//Sections
	std::vector<IMAGE_SECTION_HEADER>	vecPESections;

	//Imports
	std::vector<PEImport>		vecImports;

	FILE* fHandle;
	
public:
	PortableExecutable();
	~PortableExecutable();

	bool ReadFile(const char*);

	const char * GetFilename() const { return lpFileName; }

	//PE
	const IMAGE_DOS_HEADER* GetDOSHeader() const { return &uDOSHeader; }
	const IMAGE_NT_HEADERS* GetPEHeader() const { return &uPEHeader; }

	//Sections
	std::vector<IMAGE_SECTION_HEADER>*	GetSections() { return &vecPESections; }
	std::vector<PEImport>*				GetImports() { return &vecImports; }

	//Helpers
	DWORD GetImageBase() const;

	DWORD VirtualToRaw(DWORD dwAddress) const;

	bool ReadBytes(DWORD dwRawAddress, size_t Size, void *Dest) const;

	bool ReadCString(DWORD dwRawAddress, std::string &result) const;

	const IMAGE_SECTION_HEADER * FindSection(const char * findName) const;

	void OpenHandle();
	void CloseHandle();
};

#endif
