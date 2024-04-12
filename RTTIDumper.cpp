// RTTIDumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <cstdio>
#include <filesystem>
#include <fstream>
#include "kaitai/kaitaistream.h"
#include "parsers/mach_o/mach_o.h"

void check_binary(char* binary_path)
{
	std::ifstream input(binary_path, std::ios::binary);

	kaitai::kstream ks(&input);

	mach_o_t data(&ks);
};

int main(int argc, char* argv[])
{
	//Print help information if no arguments are supplied.
	if (argc == 1)
	{
		printf("This program attempts to dump RTTI info from binary files made using either MSVC or GCC and attempt to make header files from them.\n");
		printf("Usage: RTTIDumper.exe \"path/to/binary\"\n");
	}

	if (argc == 2) {
		char* binary_path = argv[1];
		if (std::filesystem::exists(binary_path))
			check_binary(binary_path);
	}
	else if (argc > 2)
		printf("Invalid number of arguments. Exiting.");

	return 0;
}