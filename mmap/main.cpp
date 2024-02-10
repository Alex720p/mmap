
#include <iostream>
#include "mmap.hpp"

int main()
{
    mmap mapper;
    mapper.map_dll("notepad++.exe", "message_box_tls_SHORT.dll");
    std::cout << "mapped :)" << std::endl;
}

