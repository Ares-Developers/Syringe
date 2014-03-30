#ifndef FILEHANDLE_H
#define FILEHANDLE_H

#include <stdio.h>
#include <Windows.h>

struct FileHandleDeleter {
	void operator () (FILE* file) {
		if(file) {
			fclose(file);
		}
	}
};

struct ThreadHandleDeleter {
	typedef HANDLE pointer;

	void operator () (pointer handle) {
		if(handle) {
			CloseHandle(handle);
		}
	}
};

struct ModuleHandleDeleter {
	typedef HMODULE pointer;

	void operator () (pointer handle) {
		if(handle) {
			FreeLibrary(handle);
		}
	}
};

// owns a resource. not copyable, but movable.
template <typename T, typename Deleter, T Default = T()>
struct Handle {
	explicit Handle(T value = Default) : Value(value) {}

	Handle(const Handle&) = delete;

	Handle(Handle&& other) : Value(other.Value) {
		other.Value = Default;
	};

	~Handle() {
		this->clear();
	}

	Handle& operator = (const Handle&) = delete;

	Handle& operator = (Handle&& other) {
		this->clear();
		this->Value = other.Value;
		other.Value = Default;
		return *this;
	}

	operator T () const {
		return this->Value;
	}

	void clear() {
		auto tmp = this->Value;
		this->Value = Default;

		Deleter del;
		del(tmp);
	}

private:
	T Value;
};

using FileHandle = Handle<FILE*, FileHandleDeleter, nullptr>;
using ThreadHandle = Handle<HANDLE, ThreadHandleDeleter, nullptr>;
using ModuleHandle = Handle<HMODULE, ModuleHandleDeleter, nullptr>;

#endif
