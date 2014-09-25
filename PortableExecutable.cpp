#include <algorithm>
#include <cassert>
#include <share.h>

#include "PortableExecutable.h"
#include "Handle.h"
#include "Log.h"

DWORD PortableExecutable::VirtualToRaw(DWORD dwAddress) const //address without the image base!
{
	for(const auto& uSection : vecPESections)
	{
		if(dwAddress >= uSection.VirtualAddress &&
			dwAddress < uSection.VirtualAddress + uSection.SizeOfRawData)
		{
			DWORD dwDifference = dwAddress - uSection.VirtualAddress;
			return uSection.PointerToRawData + dwDifference;
		}
	}

	return 0;
}

bool PortableExecutable::ReadFile(std::string filename)
{
	if(Filename.empty() && !filename.empty())
	{
		Filename = std::move(filename);

		if(auto F = FileHandle(_fsopen(Filename.c_str(), "rb", _SH_DENYWR)))
		{
			//DOS Header
			fread(&uDOSHeader, sizeof(IMAGE_DOS_HEADER), 1, F);
			if(uDOSHeader.e_magic == IMAGE_DOS_SIGNATURE)
			{
				//PE Header
				fseek(F, uDOSHeader.e_lfanew, SEEK_SET);
				fread(&uPEHeader, sizeof(IMAGE_NT_HEADERS), 1, F);
				if(uPEHeader.Signature == IMAGE_NT_SIGNATURE)
				{
					//Sections
					vecPESections.resize(uPEHeader.FileHeader.NumberOfSections);
					for(auto& section : vecPESections)
					{
						fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, F);
					}

					//Imports
					int import_desc_count = uPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1; //minus one for end of array
					if(import_desc_count > 0)
					{
						std::vector<IMAGE_IMPORT_DESCRIPTOR> import_desc(import_desc_count);

						fseek(
							F,
							static_cast<long>(VirtualToRaw(uPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)),
							SEEK_SET);

						for(auto& desc : import_desc) {
							fread(&desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, F);
						}

						for(const auto& desc : import_desc)
						{
							PEImport current_import;
							current_import.uDesc = desc;
							if(!current_import.uDesc.Name) {
								break;
							}

							char name_buf[0x100] = "\0";
							fseek(F, static_cast<long>(VirtualToRaw(current_import.uDesc.Name)), SEEK_SET);
							fgets(name_buf, 0x100, F);

							current_import.Name = name_buf;

							//Thunks
							PEThunkData current_thunk;

							fseek(F, static_cast<long>(VirtualToRaw(current_import.uDesc.FirstThunk)), SEEK_SET);

							for(fread(&current_thunk.uThunkData.u1, sizeof(IMAGE_THUNK_DATA), 1, F);
								current_thunk.uThunkData.u1.AddressOfData;
								fread(&current_thunk.uThunkData.u1, sizeof(IMAGE_THUNK_DATA), 1, F))
							{
								current_import.vecThunkData.push_back(current_thunk);
							}

							auto thunk_addr = reinterpret_cast<IMAGE_THUNK_DATA*>(current_import.uDesc.FirstThunk);
							for(auto& thunk : current_import.vecThunkData)
							{
								thunk.Address = reinterpret_cast<DWORD>(thunk_addr++);

								if(thunk.uThunkData.u1.AddressOfData & 0x80000000)
								{
									thunk.bIsOrdinal = true;
									thunk.Ordinal = thunk.uThunkData.u1.AddressOfData & 0x7FFFFFFF;
								}
								else
								{
									thunk.bIsOrdinal = false;

									fseek(F, static_cast<long>(VirtualToRaw(thunk.uThunkData.u1.AddressOfData & 0x7FFFFFFF)), SEEK_SET);
									fread(&thunk.wWord, 2, 1, F);
									fgets(name_buf, 0x100, F);
									thunk.Name = name_buf;
								}
							}

							vecImports.push_back(current_import);
						}
					}

					return true;
				}
			}
		}
	}

	return false;
}

DWORD PortableExecutable::GetImageBase() const {
	return this->GetPEHeader().OptionalHeader.ImageBase;
}

bool PortableExecutable::ReadBytes(DWORD dwRawAddress, size_t Size, void *Dest) const {
	if(!Filename.empty()) {
		assert(Handle);
		auto success = false;
		if(!fseek(Handle, static_cast<long>(dwRawAddress), SEEK_SET)) {
			success = (fread(Dest, Size, 1, Handle) == 1);
		}
		return success;
	}
	return false;
}

bool PortableExecutable::ReadCString(DWORD dwRawAddress, std::string &Result) const {
	if(!Filename.empty()) {
		assert(Handle);
		if(!fseek(Handle, static_cast<long>(dwRawAddress), SEEK_SET)) {
			const size_t sz = 0x100;
			char tmpBuf[sz];

			tmpBuf[0] = 0;
			if(fread(tmpBuf, 1, sz, Handle) == sz) {
				tmpBuf[sz - 1] = 0;
				Result.assign(tmpBuf);
				return true;
			}
		}
	}
	return false;
}

const IMAGE_SECTION_HEADER * PortableExecutable::FindSection(const char *findName) const {
	const size_t slen = strlen(findName);
	assert(slen <= 8);
	auto found = std::find_if(vecPESections.begin(), vecPESections.end(), [slen, findName](const decltype(*(vecPESections.begin())) & section) -> bool {
		return !memcmp(findName, section.Name, slen);
	});

	if(found == vecPESections.end()) {
		return nullptr;
	} else {
		return &(*found);
	}
}

void PortableExecutable::OpenHandle() {
	CloseHandle();

	if(!Filename.empty()) {
		Handle = FileHandle(_fsopen(Filename.c_str(), "rb", _SH_DENYNO));
	}
}

void PortableExecutable::CloseHandle() {
	Handle.clear();
}
