#pragma once

#include "Handle.h"

#include <utility>

class FindFile {
public:
	FindFile() = default;

	explicit FindFile(const char* fileName) noexcept {
		if(fileName) {
			this->Handle.reset(FindFirstFile(fileName, &this->Data));
			this->Valid = (this->Handle != INVALID_HANDLE_VALUE);
		}
	}

	explicit operator bool() const {
		return this->Valid;
	}

	FindFile& operator ++ () noexcept {
		if(this->Valid) {
			if(FindNextFile(this->Handle, &this->Data) == FALSE) {
				this->Valid = false;
				this->Handle.clear();
			}
		}
		return *this;
	}

	const WIN32_FIND_DATA* operator -> () const {
		return &this->Data;
	}

	const WIN32_FIND_DATA& operator * () const {
		return this->Data;
	}

private:
	FindHandle Handle;
	bool Valid{ false };
	WIN32_FIND_DATA Data;
};
