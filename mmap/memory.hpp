#pragma once
#pragma comment(lib, "ntdll")

#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <string> //switch to string_view later on
#include <memory>

#include "undocumented.hpp"
#include "utils.hpp"

#define FLAG_HIJACK_THREAD_FINISHED 0x1
#define PAGE_READABLE PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
#define	IS_HANDLE_VALID(handle) (handle != nullptr && handle != INVALID_HANDLE_VALUE)


//TODO: implement array of memory addresses + sizes to cleanup on destruction (have a flag in the codecave function)
class Memory {
private:
	DWORD m_proc_id = 0; //used for the get_module_handle
	HANDLE handle = INVALID_HANDLE_VALUE;
	undocumented::ntdll::PEB m_proc_peb = { 0 };
public:
	bool open_handle(const std::wstring& proc_name); //attach to process
	std::uintptr_t get_proc_image_base_addr();
	MODULEENTRY32W get_module(const std::wstring& mod_name); //TODO: change implementation like done in hijack_thread
	std::uintptr_t find_pattern(std::uintptr_t module_base_address, std::size_t module_size, const char* sig, const char* mask, int offset = 0);
	std::uintptr_t find_codecave(std::uintptr_t start, std::uintptr_t end, std::size_t size, DWORD protection_flags);
	bool hijack_thread_and_execute_shellcode(BYTE* shellcode, std::size_t shellcode_size); //function takes care of restoring flags and general purpose regsiters + restore codecave to original status

	//wrappers
	template <typename TYPE>
	TYPE read_memory(std::uintptr_t address) { //ReadProcessMemory wrapper
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		TYPE out = { 0 };
		if (!ReadProcessMemory(this->handle, reinterpret_cast<LPCVOID>(address), &out, sizeof(TYPE), nullptr))
			return {}; //read failed

		return out;
	}

	bool read_memory_with_size(std::uintptr_t address, void* out, std::size_t size) { //ReadProcessMemory wrapper
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		if (!ReadProcessMemory(this->handle, reinterpret_cast<LPCVOID>(address), out, size, nullptr))
			return NULL; //read failed

		return true;
	}

	template <typename TYPE>
	bool write_memory(std::uintptr_t dest, TYPE* data) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		return WriteProcessMemory(this->handle, reinterpret_cast<LPVOID>(dest), data, sizeof(data), nullptr);
	}

	bool write_memory_with_size(std::uintptr_t dest, void* data, std::size_t size) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		return WriteProcessMemory(this->handle, reinterpret_cast<LPVOID>(dest), data, size, nullptr);
	}

	std::uintptr_t virtual_alloc_ex(std::uintptr_t address, std::size_t size, DWORD alloc_type, DWORD protect) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		return reinterpret_cast<std::uintptr_t>(VirtualAllocEx(this->handle, reinterpret_cast<LPVOID>(address), size, alloc_type, protect));
	}

	bool virtual_protect_ex(std::uintptr_t address, std::size_t size, DWORD new_protect, DWORD* old_protect) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		return VirtualProtectEx(this->handle, reinterpret_cast<LPVOID>(address), size, new_protect, old_protect);
	}

#pragma warning(push)
#pragma warning (disable: 28160)
	bool virtual_free_ex(std::uintptr_t address, DWORD free_type, std::size_t size = 0) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		return VirtualFreeEx(this->handle, reinterpret_cast<LPVOID>(address), size, free_type);
	}
#pragma warning(pop)

	bool query_information_process(PROCESSINFOCLASS proc_info_class, void* out, std::size_t out_size) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		NTSTATUS ret = NtQueryInformationProcess(this->handle, proc_info_class, out, out_size, nullptr);

		return NT_SUCCESS(ret);
	}

	bool zero_out_memory(std::uintptr_t start, std::size_t size) {
		if (!IS_HANDLE_VALID(this->handle))
			throw std::runtime_error("No valid handle");

		std::unique_ptr<BYTE[]> zeros = std::make_unique<BYTE[]>(size);
		std::memset(zeros.get(), 0x00, size);
		return this->write_memory_with_size(start, zeros.get(), size);
	}
};