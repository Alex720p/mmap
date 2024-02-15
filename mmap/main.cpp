
#include <iostream>
#include "mmap.hpp"

int main()
{
    mmap mapper;
    //C:\\Windows\\SYSTEM32\\VCRUNTIME140.dll
    mapper.map_dll("notepad++.exe", "message_box_tls_SHORT.dll");
    //mapper.map_dll("notepad++.exe", "C:\\Windows\\SYSTEM32\\VCRUNTIME140.dll");
    std::cout << "mapped :)" << std::endl;
}

