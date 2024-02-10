#pragma once
#include "memory.hpp"
#include <fstream>

class mmap {
private:
	Memory memory;

	bool fix_relocations(char* buffer, char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, int image_delta);
	bool resolve_imports(char* buffer, char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
	bool write_buffer_to_target_process(char* buffer, char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
	bool call_tls_callbacks(char* buffer, char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header, std::size_t image_delta);
	bool call_dll_main(char* buffer, char* image, std::uintptr_t base, IMAGE_NT_HEADERS* pe_header, IMAGE_SECTION_HEADER* section_header);
public:
	bool map_dll(const char* process, const char* dll);
};