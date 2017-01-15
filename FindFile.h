#pragma once

#include "Handle.h"

#include <utility>

class FindFile {
public:
	FindFile() = default;

	explicit FindFile(char const* fileName) noexcept
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

	WIN32_FIND_DATA const* operator -> () const noexcept {
		return &this->Data;
	}

	WIN32_FIND_DATA const& operator * () const noexcept {
		return this->Data;
	}

private:
	FindHandle Handle;
	WIN32_FIND_DATA Data;
};
