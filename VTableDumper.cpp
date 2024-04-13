// VTableDumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <cstdio>
#include <filesystem>
#include <iostream>

#include "Dumper.h"

//globals
char* file_type;
char* binary_path;

void dump_macho()
{
	/*std::ifstream input(binary_path, std::ios::binary);

	kaitai::kstream ks(&input);

	mach_o_t data(&ks);*/
}

void dump_mspe()
{
	Dumper::MSPE::Dump(binary_path);
}

int main(int argc, char* argv[])
{
	//Print help information if no arguments are supplied.
	if (argc == 1)
	{
		printf("This program attempts to dump VTables from binary files made using either MSVC or GCC and attempt to make header files from them.\n");
		printf("This works best with binaries that have either RTTI or Symbols.\n");
		printf("Microsoft PE: mspe Mach object file format: macho - More types will be added soon.\n");
		printf("Usage: VTableDumper.exe \"path/to/binary\" macho/mspe\n");

		printf("\nError: No command line arguments entered, please press any key to exit.\n");
		std::cin.get();
	}

	if (argc == 3) {
		printf("Attempting to dump \"%s\" with file type \"%s\"\n", argv[1], argv[2]);

		file_type = argv[2];

		if (strcmp(file_type, "macho") != 0 && strcmp(file_type, "mspe") != 0)
		{
			printf("Error: Invalid file type.\n");
			return 1;
		}

		binary_path = argv[1];
		if (!std::filesystem::exists(binary_path))
		{
			printf("Error: Invalid file path.\n");
			return 1;
		}

		printf("Dumping...\n");
		if (strcmp(file_type, "macho") == 0)
			dump_macho();

		if (strcmp(file_type, "mspe") == 0)
			dump_mspe();
	}
	else if (argc > 3)
		printf("Error: Invalid number of arguments. Exiting.\n");

	return 0;
}