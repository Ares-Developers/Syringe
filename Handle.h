#pragma once

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <utility>

#include <stdio.h>
#include <Windows.h>

template<typename T>
struct HandleTraits {
	using type = T;

	static type default_value() noexcept {
		return T{};
	}
};

struct FileHandleTraits : public HandleTraits<FILE*> {
	static void close(FILE* file) noexcept {
		if(file) {
			fclose(file);
		}
	}
};

struct ThreadHandleTraits : public HandleTraits<HANDLE> {
	static void close(HANDLE handle) noexcept {
		if(handle) {
			CloseHandle(handle);
		}
	}
};

struct ModuleHandleTraits : public HandleTraits<HMODULE> {
	static void close(HMODULE handle) noexcept {
		if(handle) {
			FreeLibrary(handle);
		}
	}
};

struct FindHandleTraits : public HandleTraits<HANDLE> {
	static HANDLE default_value() noexcept {
		return INVALID_HANDLE_VALUE;
	}

	static void close(HANDLE handle) noexcept {
		if(handle != INVALID_HANDLE_VALUE) {
			FindClose(handle);
		}
	}
};

struct LocalAllocHandleTraits : public HandleTraits<HLOCAL> {
	static void close(HLOCAL handle) noexcept {
		LocalFree(handle);
	}
};

// owns a resource. not copyable, but movable.
template <typename Traits>
struct Handle {
	using value_type = typename Traits::type;

	Handle() noexcept = default;

	explicit Handle(value_type value) noexcept
		: Value(value)
	{ }

	Handle(Handle const&) = delete;

	Handle(Handle&& other) noexcept
		: Value(other.release())
	{ }

	~Handle() noexcept {
		if(*this) {
			Traits::close(this->Value);
		}
	}

	Handle& operator = (Handle const&) = delete;

	Handle& operator = (Handle&& other) noexcept {
		this->reset(other.release());
		return *this;
	}

	explicit operator bool() const noexcept {
		return this->Value != Traits::default_value();
	}

	operator value_type () const noexcept {
		return this->Value;
	}

	value_type get() const noexcept {
		return this->Value;
	}

	value_type release() noexcept {
		return std::exchange(this->Value, Traits::default_value());
	}

	void reset(value_type value) noexcept {
		Handle(this->Value);
		this->Value = value;
	}

	void clear() noexcept {
		Handle(std::move(*this));
	}

	value_type* set() noexcept {
		this->clear();
		return &this->Value;
	}

private:
	value_type Value{ Traits::default_value() };
};

using FileHandle = Handle<FileHandleTraits>;
using ThreadHandle = Handle<ThreadHandleTraits>;
using ModuleHandle = Handle<ModuleHandleTraits>;
using FindHandle = Handle<FindHandleTraits>;
using LocalAllocHandle = Handle<LocalAllocHandleTraits>;

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

	VirtualMemoryHandle(VirtualMemoryHandle const&) = delete;

	VirtualMemoryHandle(VirtualMemoryHandle&& other) noexcept :
		Value(std::exchange(other.Value, nullptr)),
		Process(std::exchange(other.Process, nullptr))
	{ }

	~VirtualMemoryHandle() noexcept {
		if(this->Value && this->Process) {
			VirtualFreeEx(this->Process, this->Value, 0, MEM_RELEASE);
		}
	}

	VirtualMemoryHandle& operator = (VirtualMemoryHandle const&) = delete;

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
