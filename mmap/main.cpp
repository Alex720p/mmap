
#include <iostream>
#include "mmap.hpp"

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "invalid number of paramaters" << std::endl;
    }
    else {
        Mmap mapper;
        mapper.map_dll(argv[1], argv[2]);
    }
}

