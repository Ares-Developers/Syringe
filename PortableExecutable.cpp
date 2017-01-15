#include "PortableExecutable.h"

#include "Handle.h"
#include "Log.h"

#include <algorithm>
#include <cassert>

#include <share.h>

DWORD PortableExecutable::VirtualToRaw(DWORD dwAddress) const //address without the image base!
{
	for(const auto& uSection : vecPESections)
	{
		DWORD dwDifference = dwAddress - uSection.VirtualAddress;

		if(dwDifference < uSection.SizeOfRawData) {
			return uSection.PointerToRawData + dwDifference;
		}
	}

	return 0;
}

bool PortableExecutable::ReadFile()
{
	auto const pFile = Handle.get();

	if(!pFile) {
		return false;
	}

	//DOS Header
	fseek(pFile, 0, SEEK_SET);
	fread(&uDOSHeader, sizeof(IMAGE_DOS_HEADER), 1, pFile);
	if(uDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	//PE Header
	fseek(pFile, uDOSHeader.e_lfanew, SEEK_SET);
	fread(&uPEHeader, sizeof(IMAGE_NT_HEADERS), 1, pFile);
	if(uPEHeader.Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	
	//Sections
	vecPESections.resize(uPEHeader.FileHeader.NumberOfSections);
	fread(&vecPESections[0], sizeof(IMAGE_SECTION_HEADER), vecPESections.size(), pFile);

	//Imports
	auto const& Imports = uPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(Imports.Size) {
		fseek(pFile, static_cast<long>(VirtualToRaw(Imports.VirtualAddress)), SEEK_SET);

		for(;;) {
			IMAGE_IMPORT_DESCRIPTOR import_desc;
			fread(&import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pFile);

			if(!import_desc.Name) {
				break;
			}

			vecImports.emplace_back();
			vecImports.back().uDesc = import_desc;
		}
	}

	for(auto& current_import : vecImports)
	{
		char name_buf[0x100];
		fseek(pFile, static_cast<long>(VirtualToRaw(current_import.uDesc.Name)), SEEK_SET);
		fgets(name_buf, 0x100, pFile);

		current_import.Name = name_buf;

		//Thunks
		fseek(pFile, static_cast<long>(VirtualToRaw(current_import.uDesc.FirstThunk)), SEEK_SET);

		for(;;) {
			IMAGE_THUNK_DATA thunk_data;
			fread(&thunk_data, sizeof(IMAGE_THUNK_DATA), 1, pFile);

			if(!thunk_data.u1.AddressOfData) {
				break;
			}

			current_import.vecThunkData.emplace_back();
			current_import.vecThunkData.back().uThunkData = thunk_data;
		}

		auto thunk_addr = reinterpret_cast<IMAGE_THUNK_DATA*>(current_import.uDesc.FirstThunk);
		for(auto& thunk : current_import.vecThunkData)
		{
			thunk.Address = reinterpret_cast<DWORD>(thunk_addr++);

			if(thunk.uThunkData.u1.AddressOfData & 0x80000000)
			{
				thunk.bIsOrdinal = true;
				thunk.Ordinal = static_cast<int>(thunk.uThunkData.u1.AddressOfData & 0x7FFFFFFFu);
			}
			else
			{
				thunk.bIsOrdinal = false;

				fseek(pFile, static_cast<long>(VirtualToRaw(thunk.uThunkData.u1.AddressOfData & 0x7FFFFFFF)), SEEK_SET);
				fread(&thunk.wWord, 2, 1, pFile);
				fgets(name_buf, 0x100, pFile);
				thunk.Name = name_buf;
			}
		}
	}

	return true;
}

DWORD PortableExecutable::GetImageBase() const {
	return this->GetPEHeader().OptionalHeader.ImageBase;
}

bool PortableExecutable::ReadBytes(
	DWORD const dwRawAddress, size_t const Size, void* const Dest) const
{
	if(auto const pFile = Handle.get()) {
		if(!fseek(pFile, static_cast<long>(dwRawAddress), SEEK_SET)) {
			return (fread(Dest, Size, 1, pFile) == 1);
		}
	}
	return false;
}

bool PortableExecutable::ReadCString(
	DWORD const dwRawAddress, std::string& Result) const
{
	if(auto const pFile = Handle.get()) {
		if(!fseek(pFile, static_cast<long>(dwRawAddress), SEEK_SET)) {
			constexpr size_t sz = 0x100;
			char tmpBuf[sz];

			tmpBuf[0] = 0;
			if(fread(tmpBuf, 1, sz, pFile) == sz) {
				tmpBuf[sz - 1] = 0;
				Result.assign(tmpBuf);
				return true;
			}
		}
	}
	return false;
}

IMAGE_SECTION_HEADER const* PortableExecutable::FindSection(
	std::string_view const name) const noexcept
{
	assert(name.size() <= IMAGE_SIZEOF_SHORT_NAME);
	char buffer[IMAGE_SIZEOF_SHORT_NAME] = {};
	std::memcpy(buffer, name.data(), name.size());

	auto const found = std::find_if(
		vecPESections.cbegin(), vecPESections.cend(),
		[&buffer](auto const& section) {
			return !memcmp(section.Name, buffer, std::size(buffer));
		});

	if(found == vecPESections.cend()) {
		return nullptr;
	} else {
		return &(*found);
	}
}
