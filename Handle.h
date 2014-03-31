#ifndef FILEHANDLE_H
#define FILEHANDLE_H

#include <stdio.h>
#include <Windows.h>
#include <utility>

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

struct FindHandleDeleter {
	typedef HANDLE pointer;

	void operator () (pointer handle) {
		if(handle != INVALID_HANDLE_VALUE) {
			FindClose(handle);
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
using FindHandle = Handle<HANDLE, FindHandleDeleter, INVALID_HANDLE_VALUE>;

struct VirtualMemoryHandle {
	VirtualMemoryHandle() : Value(nullptr), Process(nullptr) {}
	VirtualMemoryHandle(HANDLE process, void* address, size_t size) : VirtualMemoryHandle() {
		if(process && size) {
			this->Value = VirtualAllocEx(process, address, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		}
	}

	VirtualMemoryHandle(const VirtualMemoryHandle&) = delete;

	VirtualMemoryHandle(VirtualMemoryHandle&& other) {
		*this = std::move(other);
	};

	~VirtualMemoryHandle() {
		this->clear();
	}

	VirtualMemoryHandle& operator = (const VirtualMemoryHandle&) = delete;

	VirtualMemoryHandle& operator = (VirtualMemoryHandle&& other) {
		this->clear();
		std::swap(this->Value, other.Value);
		std::swap(this->Process, other.Process);
		return *this;
	}

	operator BYTE*() const {
		return static_cast<BYTE*>(this->Value);
	}

	void clear() {
		auto val = this->Value;
		auto proc = this->Process;
		this->Value = nullptr;
		this->Process = nullptr;

		if(val && proc) {
			VirtualFreeEx(proc, val, 0, MEM_RELEASE);
		}
	}

private:
	void* Value;
	HANDLE Process;
};

#endif
