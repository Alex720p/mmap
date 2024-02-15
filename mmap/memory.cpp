#include "./memory.hpp"

bool Memory::open_handle(const std::wstring& proc_name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot, &proc_entry)) {
		while (Process32Next(snapshot, &proc_entry)) {
			if (!proc_name.compare(proc_entry.szExeFile)) { //in this case == 0 means that the strings are 'equal'
				this->m_proc_id = proc_entry.th32ProcessID;
				this->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_entry.th32ProcessID);
				break;
			}
		}
	}

	CloseHandle(snapshot);
	return IS_HANDLE_VALID(this->handle);
}

std::uintptr_t Memory::get_proc_image_base_addr() {
	if (!IS_HANDLE_VALID(this->handle))
		throw std::runtime_error("No valid handle");

	if (this->m_proc_peb.ImageBaseAddress != NULL)
		return reinterpret_cast<std::uintptr_t>(this->m_proc_peb.ImageBaseAddress);

	PROCESS_BASIC_INFORMATION proc_basic_info = { 0 };
	if (!this->query_information_process(ProcessBasicInformation, &proc_basic_info, sizeof(PROCESS_BASIC_INFORMATION)))
		return 0;

	undocumented::ntdll::PEB target_proc_peb = { 0 };
	if (!this->read_memory_with_size(reinterpret_cast<std::uintptr_t>(proc_basic_info.PebBaseAddress), &target_proc_peb, sizeof(undocumented::ntdll::PEB)))
		return 0;

	this->m_proc_peb = target_proc_peb;
	return reinterpret_cast<std::uintptr_t>(this->m_proc_peb.ImageBaseAddress);
}

MODULEENTRY32W Memory::get_module(const std::wstring& mod_name) {
	if (!IS_HANDLE_VALID(this->handle))
		throw std::runtime_error("No valid handle");

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_proc_id);
	MODULEENTRY32 mod_entry;
	mod_entry.dwSize = sizeof(MODULEENTRY32);
	bool found = false;
	if (Module32First(snapshot, &mod_entry)) {
		while (Module32Next(snapshot, &mod_entry)) {
			if (!_wcsicmp(mod_name.c_str(), mod_entry.szModule)) {
				found = true;
				break;
			}

		}
	}

	if (found)
		return mod_entry;
	else
		return { 0 };
}

std::uintptr_t Memory::find_pattern(std::uintptr_t module_base_address, std::size_t module_size, const char* sig, const char* mask, int offset) {
	if (!IS_HANDLE_VALID(this->handle))
		throw std::runtime_error("No valid handle");

	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	std::unique_ptr<char[]> page = std::make_unique<char[]>(mem_basic_info.RegionSize + strlen(mask));//structure: old page content (size of mask) for sig across pages and new page content (size of region)
	for (std::size_t i = 0; i < module_size; i += mem_basic_info.RegionSize) { //going throught the regions
		VirtualQueryEx(this->handle, reinterpret_cast<LPCVOID>(module_base_address), &mem_basic_info, sizeof(mem_basic_info)); //getting the regions size in mem_basic_info
		if (!(mem_basic_info.Protect & PAGE_READABLE)) {
			DWORD old_protect;
			VirtualProtectEx(this->handle, reinterpret_cast<LPVOID>(module_base_address + i), mem_basic_info.RegionSize, PAGE_READONLY, &old_protect);

			bool ret = this->read_memory_with_size(module_base_address + i, page.get() + strlen(mask), mem_basic_info.RegionSize);

			VirtualProtectEx(this->handle, reinterpret_cast<LPVOID>(module_base_address + i), mem_basic_info.RegionSize, old_protect, &old_protect);

			if (!ret)
				return false;
		}
		else {
			if (!this->read_memory_with_size(module_base_address + i, page.get() + strlen(mask), mem_basic_info.RegionSize))
				return false;
		}

		for (std::size_t j = 0; j < mem_basic_info.RegionSize; j++) {
			for (std::size_t k = 0; k < strlen(mask); k++) {
				if (page[j + k] != sig[k] && mask[k] != '?')
					break; //sequence not matching sig, break and go next

				if (k == strlen(mask) - 1)
					return i + j - strlen(mask) + offset; // sig found !
			}
		}
		std::memcpy(page.get(), page.get() + mem_basic_info.RegionSize, strlen(mask)); //copy the end of the page for across pages sig
	}
	return 0;
}

#pragma warning(push)
#pragma warning(disable: 6385)
std::uintptr_t Memory::find_codecave(std::uintptr_t start, std::uintptr_t end, std::size_t size, DWORD protection_flags) {
	if (!IS_HANDLE_VALID(this->handle))
		throw std::runtime_error("No valid handle");

	MEMORY_BASIC_INFORMATION mem_info = { 0 };
	std::uintptr_t query_addr = start;

	while (query_addr < end) {
		std::size_t bytes_read = VirtualQueryEx(this->handle, reinterpret_cast<LPCVOID>(query_addr), &mem_info, sizeof(mem_info));
		if (!bytes_read)
			return 0; //VirtualQuery failed (no more page to scan, ...)

		query_addr = reinterpret_cast<std::uintptr_t>(mem_info.BaseAddress); //need to set it to BaseAddress if one of the pages protection has been modified resulting in a split

		if (mem_info.Protect & protection_flags && !(mem_info.Protect & PAGE_GUARD) &&  mem_info.State == MEM_COMMIT) { 
			std::unique_ptr<char[]> page = std::make_unique<char[]>(mem_info.RegionSize);
			if (!this->read_memory_with_size(query_addr, page.get(), mem_info.RegionSize)) {
				int temp = GetLastError();
				return 0; //failed to read memory //TODO: some error here, should prob not exit and copntinue
			}

			for (std::size_t i = mem_info.RegionSize - 1; i >= size - 1; i--) {
				for (std::size_t j = 0; j <= size; j++) {
					if (j == size)
						return query_addr + i - j + 1;;

					if (page[i - j] != 0x00)
						break;
				}
			}
		}
		query_addr += mem_info.RegionSize;
	}
	return 0; //no codecave found
}
#pragma warning(pop)

bool Memory::hijack_thread_and_execute_shellcode(BYTE* shellcode, std::size_t shellcode_size) { //note: no need for cleanup in the shellcode passed in args
	if (!IS_HANDLE_VALID(this->handle))
		throw std::runtime_error("No valid handle");

	/*
		start_restore: //TODO: store xmm regs IMPORTANT
		pushfq	; push flags on stack
		push rax ; push all caller saved registers
		push rdi
		push rsi
		push rdx
		push rcx
		push r8
		push r9
		push r10
		push r11

		push rsp ; align the stack to a multiple of 0x10 (C calling convention :))))
		push [rsp]
		and rsp, -0x10

		sub rsp, 0x20 ; calling convention, need to reverse this space in the stack for the function called
	*/

	BYTE start_restore_orig_state[] = { 0x9C, 0x50, 0x57, 0x56, 0x52, 0x51, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x54, 0xFF, 0x34, 0x24, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20 };

	/*
		end_restore:
			mov rax, <byte check addr>
			mov byte ptr [rax], 0x1 ;set byte to indicate our shellcode has finished

			add rsp, 0x20 ; restore the space reserved

			mov rsp, [rsp + 8] ; restore old stack alignment

			pop r11
			pop r10
			pop r9
			pop r8
			pop rcx
			pop rdx
			pop rsi
			pop rdi
			pop rax
			popfq

			jmp qword ptr [rip] ; resume to old control flow
			<old rip here> ; since we jump to rip, it will take this value for the jump. This way we can make an absolute jump //https://stackoverflow.com/questions/9815448/jmp-instruction-hex-code
	*/

	BYTE end_restore_orig_state[] = {0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xC6, 0x00, 0x01, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x8B, 0x64, 0x24, 0x08, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x59, 0x5A, 0x5E, 0x5F, 0x58, 0x9D, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE };


	std::size_t complete_shellcode_size = sizeof(start_restore_orig_state) + shellcode_size + sizeof(end_restore_orig_state);

	//we'll first check for a codecave, if it doesn't exists we create a page ourself
	std::uintptr_t shellcode_address_target = this->find_codecave(0, UINT64_MAX, complete_shellcode_size, PAGE_EXECUTE_READWRITE);
	bool allocated = false;
	if (!shellcode_address_target) {
		shellcode_address_target = this->virtual_alloc_ex(NULL, complete_shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!shellcode_address_target)
			return 0;
		else
			allocated = true;
	}

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->m_proc_id);
	if (!IS_HANDLE_VALID(snapshot))
		return false;

	THREADENTRY32 thread_entry = { 0 };
	thread_entry.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(snapshot, &thread_entry))
		return false;

	bool success = false;
	do {
		if (thread_entry.th32OwnerProcessID != this->m_proc_id)
			continue;

		HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_entry.th32ThreadID);
		if (IS_HANDLE_VALID(thread)) {
			if (SuspendThread(thread) != (DWORD)-1) {
				CONTEXT context = { 0 };
				context.ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(thread, &context)) {
					std::memcpy(&end_restore_orig_state[2], &shellcode_address_target, sizeof(std::uintptr_t)); //where the FLAG_HIJACK_THREAD_FINISHED will be set 
					std::memcpy(&end_restore_orig_state[42], &context.Rip, sizeof(std::uintptr_t)); //copy the old eip into 'restore' shellcode
					context.Rip = shellcode_address_target;

					std::unique_ptr<BYTE[]> complete_shellcode = std::make_unique<BYTE[]>(complete_shellcode_size);
					std::memcpy(complete_shellcode.get(), start_restore_orig_state, sizeof(start_restore_orig_state));
					std::memcpy(&complete_shellcode[sizeof(start_restore_orig_state)], shellcode, shellcode_size);
					std::memcpy(&complete_shellcode[sizeof(start_restore_orig_state) + shellcode_size], end_restore_orig_state, sizeof(end_restore_orig_state));
					if (this->write_memory_with_size(shellcode_address_target, complete_shellcode.get(), complete_shellcode_size)) {
						SetThreadContext(thread, &context);
						ResumeThread(thread);
						while (this->read_memory<BYTE>(shellcode_address_target) != FLAG_HIJACK_THREAD_FINISHED)
							Utils::sleep(10);

						success = true;
					}
					else {
						ResumeThread(thread);
					}
				}
			}
			CloseHandle(thread);
		}
		if (success)
			break;
	} while (Thread32Next(snapshot, &thread_entry));

	if (!allocated)
		this->zero_out_memory(shellcode_address_target, complete_shellcode_size);
	else
		this->virtual_free_ex(shellcode_address_target, MEM_RELEASE);

	CloseHandle(snapshot);

	return success;
}