#include "mmap.hpp"

std::uintptr_t mmap::map_dll(const char* process, const char* dll) {
	std::ifstream file(dll, std::ios_base::binary);

	if (!file.is_open())
		Utils::print_and_exit("Invalid dll path");

	if (!this->memory.open_handle(Utils::get_wstring_from_char(process)))
		Utils::print_and_exit("Failed to get handle to process");

	file.seekg(0, file.end);
	std::size_t file_size = file.tellg();
	file.seekg(0, file.beg);

	std::unique_ptr<char[]> buffer = std::make_unique<char[]>(file_size);
	file.read(buffer.get(), file_size);

	IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.get());
	IMAGE_NT_HEADERS* pe_header = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.get() + dos_header->e_lfanew);

	std::uintptr_t base = memory.virtual_alloc_ex(NULL, pe_header->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE); //we'll just let virtualalloc choose the address and rebase after
	if (!base)
		return false;

	std::printf("[+] Dll Base: 0x%llx \n", base);
	try {
		std::unique_ptr<char[]> image = std::make_unique<char[]>(pe_header->OptionalHeader.SizeOfImage); //will do all the base reloc etc in curr process memory and write it at once into target
		std::size_t image_delta = base - pe_header->OptionalHeader.ImageBase;
		IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(pe_header);
		//loading the dll into our buffer to make all fixing inside the mapper
		for (std::size_t i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
			std::uintptr_t section_rva = section_header[i].VirtualAddress;
			std::size_t section_size_disk = section_header[i].SizeOfRawData;
			std::size_t section_size_memory = section_header[i].Misc.VirtualSize;

			std::uintptr_t dest = memory.virtual_alloc_ex(base + section_rva, section_size_memory, MEM_COMMIT, PAGE_READWRITE);
			std::memcpy(image.get() + section_rva, buffer.get() + section_header[i].PointerToRawData, section_size_disk);
		}


		this->fix_relocations(image.get(), base, pe_header, section_header, image_delta);
		std::printf("[+] Fixed relocations \n");

		this->resolve_imports(image.get(), base, pe_header, section_header);
		std::printf("[+] Fixed relocations \n");

		this->write_buffer_to_target_process(image.get(), base, pe_header, section_header);
		std::printf("[+] Dll written into target process memory \n");

		this->call_tls_callbacks(image.get(), base, pe_header, section_header, image_delta);
		std::printf("[+] Called DLL_PROCESS_ATTACH TLS callbacks \n");

		this->call_dll_main(image.get(), base, pe_header, section_header);
		std::printf("[+] Called Dll Main into target process \n");

		return base;
	}
	catch (std::runtime_error& err) {
		this->memory.virtual_free_ex(base, MEM_RELEASE);
		Utils::print_and_exit(err.what());
		return 0;
	}
	catch (...) {
		this->memory.virtual_free_ex(base, MEM_RELEASE);
		Utils::print_and_exit("Unexpected error happened, make sure the dll is valid/not corrupt");
		return 0;
	}


}

bool mmap::fix_relocations(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, std::size_t image_delta) {
	IMAGE_DATA_DIRECTORY base_reloc_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	std::size_t offset_to_block_start = 0;

	while (offset_to_block_start < base_reloc_dir.Size) {
		IMAGE_BASE_RELOCATION* base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + base_reloc_dir.VirtualAddress + offset_to_block_start);
		std::size_t num_of_entries = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); //num of entries in the reloc block

		void* block = image + base_reloc_dir.VirtualAddress + offset_to_block_start + sizeof(IMAGE_BASE_RELOCATION);
		std::uintptr_t page = reinterpret_cast<std::uintptr_t>(image + base_relocation->VirtualAddress); //page where the fixing is needed

		WORD* entry = reinterpret_cast<WORD*>(block);
		for (std::size_t j = 0; j < num_of_entries; j++) {
			BYTE relocation_type = entry[j] >> 12;
			WORD offset = entry[j] & 0xFFF;

			if (relocation_type == IMAGE_REL_BASED_ABSOLUTE)
				continue; //padding, we skip
			else if (relocation_type == IMAGE_REL_BASED_HIGHLOW)
				*reinterpret_cast<uint32_t*>(page + offset) += (image_delta & UINT32_MAX);
			else if (relocation_type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(page + offset) += image_delta;
			else
				throw std::runtime_error("Unsupported relocation type");
		}

		offset_to_block_start += base_relocation->SizeOfBlock;
	}

	return true;
}

bool mmap::resolve_imports(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header) {
	IMAGE_DATA_DIRECTORY import_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_DATA_DIRECTORY bound_image_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];

	std::uintptr_t import_desc_start_address = reinterpret_cast<std::uintptr_t>(image) + import_dir.VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_desc_start_address);
	while (import_dir.Size > sizeof(IMAGE_IMPORT_DESCRIPTOR) + (reinterpret_cast<std::uintptr_t>(import_descriptor) - import_desc_start_address)) { //TODO: change condition here, it's ugly
		LPCSTR module_name_ptr = reinterpret_cast<LPCSTR>(image + import_descriptor->Name);
		std::string module_name = std::string(module_name_ptr);
		if (module_name.find(VIRTUAL_DLL_PREFIX) != std::string::npos) {
			module_name = Utils::get_dll_name_from_api_set_map(module_name);  //virtual dll -> get real dll
			module_name_ptr = module_name.c_str();
		}

		std::wstring module_name_wide = Utils::get_wstring_from_char(module_name_ptr);
		HMODULE fn_module_target = memory.get_module(module_name_wide).hModule;
		HMODULE fn_module_local = LoadLibraryA(module_name_ptr);
		if (!fn_module_target) {
			std::unique_ptr<char[]> dependency_file_path = std::make_unique<char[]>(MAX_PATH);
			if (!GetModuleFileNameA(fn_module_local, dependency_file_path.get(), MAX_PATH))
				throw std::runtime_error("Failed to get import dependency path for" + module_name);

			fn_module_target = reinterpret_cast<HMODULE>(this->map_dll("notepad++.dll", dependency_file_path.get())); //todo: change to correct app name

			/*if (!strstr(dependency_file_path.get(), WINDOWS_DLL_START_PATH)) //manual mapping some officials windows dll causes an access violation, until I figure it out this will have to do
				fn_module_target = reinterpret_cast<HMODULE>(this->map_dll("notepad++.dll", dependency_file_path.get()));
			else {
				// Shellcode:
				//mov rcx, <ptr to module name str>
				//mov rax, <LoadLibA addr>
				//call rax
				

				BYTE shellcode[] = {0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0};
				std::uintptr_t dll_name_base = memory.find_codecave(0, UINT64_MAX, lstrlenA(module_name_ptr) + 1, PAGE_READWRITE);
				if (!dll_name_base)
					throw std::runtime_error("Failed to find a codecave");

				std::uintptr_t loadLibrary_address = reinterpret_cast<std::uintptr_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

				std::memcpy(&shellcode[2], &dll_name_base, sizeof(std::uintptr_t)); //copy module name addr into shellcode
				std::memcpy(&shellcode[12], &loadLibrary_address, sizeof(std::uintptr_t)); //copy LoadLibrary func address

				if (!memory.write_memory_with_size(dll_name_base, (void*)module_name_ptr, lstrlenA(module_name_ptr) + 1)) //probably doing something very ugly here with the (void*) cast but it works :)
					throw std::runtime_error("Something went wrong writing to process memory");

				if (!memory.hijack_thread_and_execute_shellcode(shellcode, sizeof(shellcode)))
					throw std::runtime_error("Failed to import dll dependencies into target process");

				memory.zero_out_memory(dll_name_base, lstrlenA(module_name_ptr));

				while (!fn_module_target) {
					fn_module_target = memory.get_module(module_name_wide).hModule;
					Sleep(10);
				}
			}		*/
		}

		if (!fn_module_target || !fn_module_local)
			throw std::runtime_error("Failed to get import dependency " + module_name + " base address");

		std::uintptr_t fn_module_delta = reinterpret_cast<std::uintptr_t>(fn_module_target) - reinterpret_cast<std::uintptr_t>(fn_module_local);

		IMAGE_THUNK_DATA* import_lookup_table = reinterpret_cast<IMAGE_THUNK_DATA*>(image + import_descriptor->OriginalFirstThunk);
		IMAGE_THUNK_DATA* import_address_table = reinterpret_cast<IMAGE_THUNK_DATA*>(image + import_descriptor->FirstThunk);

		std::uintptr_t* ilt_entry = reinterpret_cast<std::uintptr_t*> (import_lookup_table);
		std::uintptr_t* iat_entry = reinterpret_cast<std::uintptr_t*>(import_address_table);
		while (*ilt_entry != 0) {
			std::uintptr_t fn_address_local;
			if (*ilt_entry & IMAGE_ORDINAL_FLAG64) { //import by ordinal
				std::uintptr_t fn_ordinal = IMAGE_ORDINAL64(*ilt_entry);
				fn_address_local = reinterpret_cast<std::uintptr_t>(GetProcAddress(fn_module_local, MAKEINTRESOURCEA(fn_ordinal)));
			} else { //import by name
				IMAGE_IMPORT_BY_NAME* import_info = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + *ilt_entry);
				LPCSTR fn_name = reinterpret_cast<LPCSTR>(&import_info->Name);
				fn_address_local = reinterpret_cast<std::uintptr_t>(GetProcAddress(fn_module_local, fn_name));
			}

			*iat_entry = fn_address_local + fn_module_delta;

			ilt_entry++;
			iat_entry++;
		}

		if (import_descriptor->TimeDateStamp == -1) { //if bound, note: since we're very unlikely to get dll loaded at prefered address, won't bother checking if bound for each of the entries
			IMAGE_BOUND_IMPORT_DESCRIPTOR* image_bound_descriptor = reinterpret_cast<IMAGE_BOUND_IMPORT_DESCRIPTOR*>(image + bound_image_dir.VirtualAddress);
			import_descriptor->TimeDateStamp = image_bound_descriptor->TimeDateStamp;
		}
		else
			import_descriptor->TimeDateStamp = pe_header->FileHeader.TimeDateStamp; //dummy

		import_descriptor++;
	}

	return true;
}

bool mmap::write_buffer_to_target_process(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header) {
	//writing image buffer into target memory
	for (std::size_t i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
		if (!lstrcmpA(reinterpret_cast<LPCSTR>(section_header[i].Name), ".reloc"))
			continue; //doens't have a purpose once loaded into memory, deleting it will make it more troublesome for someone to get the dll from memory

		std::uintptr_t section_rva = section_header[i].VirtualAddress;
		std::size_t section_size = section_header[i].SizeOfRawData;
		if (!memory.write_memory_with_size(base + section_rva, image + section_rva, section_size))
			throw std::runtime_error("Failed to write to process memory");

		//fix memory protections to correct flags
		DWORD protection;
		if (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			if (section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				protection = PAGE_EXECUTE_READWRITE;
			else if (section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
				protection = PAGE_EXECUTE_READ;
			else
				protection = PAGE_EXECUTE;
		}
		else {
			if (section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				protection = PAGE_READWRITE;
			else if (section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
				protection = PAGE_READONLY;
			else if (section_header[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
				protection = PAGE_NOCACHE;
			else
				protection = PAGE_NOACCESS;
		}

		DWORD old_protection; //dummy variable, VirtualProtectEx fails if old_protection not passed
		if (!memory.virtual_protect_ex(base + section_rva, section_size, protection, &old_protection))
			throw std::runtime_error("Failed to call VirtualProtect on target process");
	}

	return true;
}

//https://legend.octopuslabs.io/archives/2418/2418.htm
//IMPORTANT: we need the untouched buffer here (the one where no base relocs have been done)
bool mmap::call_tls_callbacks(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, std::size_t image_delta) {
	//calling tls callbacks
	IMAGE_DATA_DIRECTORY tls_dir_entry = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	/*	shellcode:
		movq rcx, <base addr of dll>
		movq rdx, 0x1
		movq r8, 0x0
		movq rax, <addr of callback>
		call rax
	*/

	if (tls_dir_entry.Size) {
		BYTE shellcode[] = { 0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0 };
		std::memcpy(&shellcode[2], &base, sizeof(HMODULE));

		IMAGE_TLS_DIRECTORY* tls_dir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(image + tls_dir_entry.VirtualAddress);
		std::uintptr_t* callbacks = reinterpret_cast<std::uintptr_t*>(image - pe_header->OptionalHeader.ImageBase + tls_dir->AddressOfCallBacks - image_delta); //ptr the the first elem of an array of callbacks (we subtract the image_delta to revert the changes from the reloc done before)

		while (*callbacks) {
			std::uintptr_t callback_addr_in_target = *callbacks; //note: the address of the callback already matches the one in memory since we did the relocations before
			std::memcpy(&shellcode[26], &callback_addr_in_target, sizeof(std::uintptr_t));
			if (!memory.hijack_thread_and_execute_shellcode(shellcode, sizeof(shellcode)))
				throw std::runtime_error("Failed to call tls callbacks");

			callbacks++;
		}
	}
	return true;

}

bool mmap::call_dll_main(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header) {
	/* Shellcode:
		movq rcx, <HMODULE of dll> ; HMODULE of dll
		movq rdx, 0x1 ; fdwReason DLL_PROCESS_ATTACH
		movq r8, 0x0 ; lpvReserved 0 for DLL_PROCESS_ATTACH
		movq rax, <DLLMain>
		call rax
	*/

	BYTE shellcode[] = { 0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0 };
	std::uintptr_t dll_entrypoint = base + pe_header->OptionalHeader.AddressOfEntryPoint;
	std::memcpy(&shellcode[2], &base, sizeof(HMODULE));
	std::memcpy(&shellcode[26], &dll_entrypoint, sizeof(std::uintptr_t));

	if (!memory.hijack_thread_and_execute_shellcode(shellcode, sizeof(shellcode)))
		throw std::runtime_error("Failed to call dll entry point");

	return true;
}