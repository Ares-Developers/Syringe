#pragma once

#include <stdio.h>
#include <Windows.h>
#include <utility>

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

private:
	T Value{ Default };
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

