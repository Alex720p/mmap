#pragma once
#include "memory.hpp"
#include <fstream>

#define WINDOWS_DLL_START_PATH "C:\\Windows\\SYSTEM32\\"

class mmap {
private:
	Memory memory;

	bool fix_relocations(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, std::size_t image_delta);
	bool resolve_imports(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
	bool write_buffer_to_target_process(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
	bool call_tls_callbacks(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, std::size_t image_delta);
	bool call_dll_main(char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
public:
	std::uintptr_t map_dll(const char* process, const char* dll);
};