#pragma once

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <utility>

#include <stdio.h>
#include <Windows.h>

struct FileHandleDeleter {
	void operator () (FILE* file) const noexcept {
		if(file) {
			fclose(file);
		}
	}
};

struct ThreadHandleDeleter {
	using pointer = HANDLE;

	void operator () (pointer handle) const noexcept {
		if(handle) {
			CloseHandle(handle);
		}
	}
};

struct ModuleHandleDeleter {
	using pointer = HMODULE;

	void operator () (pointer handle) const noexcept {
		if(handle) {
			FreeLibrary(handle);
		}
	}
};

struct FindHandleDeleter {
	using pointer = HANDLE;

	void operator () (pointer handle) const noexcept {
		if(handle != INVALID_HANDLE_VALUE) {
			FindClose(handle);
		}
	}
};

struct LocalAllocHandleDeleter {
	using pointer = HLOCAL;

	void operator () (pointer handle) const noexcept {
		LocalFree(handle);
	}
};

// owns a resource. not copyable, but movable.
template <typename T, typename Deleter, T Default = T()>
struct Handle {
	constexpr Handle() noexcept = default;

	constexpr explicit Handle(T value) noexcept
		: Value(value)
	{ }

	Handle(const Handle&) = delete;

	constexpr Handle(Handle&& other) noexcept
		: Value(other.release())
	{ }

	~Handle() noexcept {
		if(this->Value != Default) {
			Deleter{}(this->Value);
		}
	}

	Handle& operator = (const Handle&) = delete;

	Handle& operator = (Handle&& other) noexcept {
		this->reset(other.release());
		return *this;
	}

	constexpr explicit operator bool() const noexcept {
		return this->Value != Default;
	}

	constexpr operator T () const noexcept {
		return this->Value;
	}

	constexpr T get() const noexcept {
		return this->Value;
	}

	T release() noexcept {
		return std::exchange(this->Value, Default);
	}

	void reset(T value) noexcept {
		Handle(this->Value);
		this->Value = value;
	}

	void clear() noexcept {
		Handle(std::move(*this));
	}

	T* set() noexcept {
		this->clear();
		return &this->Value;
	}

private:
	T Value{ Default };
};

using FileHandle = Handle<FILE*, FileHandleDeleter, nullptr>;
using ThreadHandle = Handle<HANDLE, ThreadHandleDeleter, nullptr>;
using ModuleHandle = Handle<HMODULE, ModuleHandleDeleter, nullptr>;
using FindHandle = Handle<HANDLE, FindHandleDeleter, INVALID_HANDLE_VALUE>;
using LocalAllocHandle = Handle<HLOCAL, LocalAllocHandleDeleter, nullptr>;

struct VirtualMemoryHandle {
	VirtualMemoryHandle() noexcept = default;

	VirtualMemoryHandle(HANDLE process, void* address, size_t size) noexcept
		: Process(process)
	{
		if(process && size) {
			this->Value = VirtualAllocEx(process, address, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		}
	}

	VirtualMemoryHandle(void* pAllocated, HANDLE process) noexcept
		: Value(pAllocated), Process(process)
	{ }

	VirtualMemoryHandle(const VirtualMemoryHandle&) = delete;

	VirtualMemoryHandle(VirtualMemoryHandle&& other) noexcept :
		Value(std::exchange(other.Value, nullptr)),
		Process(std::exchange(other.Process, nullptr))
	{ }

	~VirtualMemoryHandle() noexcept {
		if(this->Value && this->Process) {
			VirtualFreeEx(this->Process, this->Value, 0, MEM_RELEASE);
		}
	}

	VirtualMemoryHandle& operator = (const VirtualMemoryHandle&) = delete;

	VirtualMemoryHandle& operator = (VirtualMemoryHandle&& other) noexcept {
		VirtualMemoryHandle(this->Value, this->Process);
		this->Value = std::exchange(other.Value, nullptr);
		this->Process = std::exchange(other.Process, nullptr);
		return *this;
	}

	operator BYTE*() const noexcept {
		return this->get();
	}

	BYTE* get() const noexcept {
		return static_cast<BYTE*>(this->Value);
	}

	void clear() noexcept {
		VirtualMemoryHandle(std::move(*this));
	}

private:
	void* Value{ nullptr };
	HANDLE Process{ nullptr };
};
