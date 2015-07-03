#pragma once

#include "Handle.h"

#include <utility>

class FindFile {
public:
	explicit FindFile(const char* fileName = nullptr) : Valid(false) {
		if(fileName) {
			this->Handle = FindHandle(FindFirstFile(fileName, &this->Data));
			this->Valid = (this->Handle != INVALID_HANDLE_VALUE);
		}
	}

	FindFile(const FindFile&) = delete;

	FindFile(FindFile&& other) {
		*this = std::move(other);
	}

	FindFile& operator = (const FindFile&) = delete;

	FindFile& operator = (FindFile&& other) {
		std::swap(this->Handle, other.Handle);
		std::swap(this->Valid, other.Valid);
		std::swap(this->Data, other.Data);
		return *this;
	}

	explicit operator bool() const {
		return this->Valid;
	}

	FindFile& operator ++ () {
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
	WIN32_FIND_DATA Data;
	FindHandle Handle;
	bool Valid;
};
