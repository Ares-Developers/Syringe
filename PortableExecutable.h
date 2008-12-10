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
	
	//Helpers
	DWORD VirtualToRaw(DWORD dwAddress);

public:
	PortableExecutable();
	~PortableExecutable();

	bool ReadFile(const char*);

	//PE
	const IMAGE_DOS_HEADER* GetDOSHeader(){return &uDOSHeader;}
	const IMAGE_NT_HEADERS* GetPEHeader(){return &uPEHeader;}

	//Sections
	std::vector<IMAGE_SECTION_HEADER>*	GetSections(){return &vecPESections;}
	std::vector<PEImport>*				GetImports(){return &vecImports;}
};

#endif
