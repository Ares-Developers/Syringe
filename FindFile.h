#pragma once

#include "Handle.h"

#include <utility>

class FindFile {
public:
	FindFile() = default;

	explicit FindFile(const char* fileName) noexcept
		: Handle(FindFirstFile(fileName, &this->Data))
	{ }

	explicit operator bool() const noexcept {
		return static_cast<bool>(this->Handle);
	}

	FindFile& operator ++ () noexcept {
		if(this->Handle) {
			if(FindNextFile(this->Handle, &this->Data) == FALSE) {
				this->Handle.clear();
			}
		}
		return *this;
	}

	const WIN32_FIND_DATA* operator -> () const noexcept {
		return &this->Data;
	}

	const WIN32_FIND_DATA& operator * () const noexcept {
		return this->Data;
	}

private:
	FindHandle Handle;
	WIN32_FIND_DATA Data;
};
