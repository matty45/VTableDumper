// VTableDumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "kaitai/kaitaistream.h"
#include "parsers/mach_o/mach_o.h"
#include "parsers/microsoft_pe/microsoft_pe.h"

//globals
char* file_type;
char* binary_path;

void dump_macho()
{
	std::ifstream input(binary_path, std::ios::binary);

	kaitai::kstream ks(&input);

	mach_o_t data(&ks);
}

std::vector<microsoft_pe_t::section_t*> read_only_sections;
std::vector<microsoft_pe_t::section_t*> executable_sections;

void dump_mspe()
{
	std::ifstream input(binary_path, std::ios::binary);

	kaitai::kstream ks(&input);

	microsoft_pe_t data(&ks);

	// Get pe sections and iterate through them.
	std::vector<microsoft_pe_t::section_t*>* sections = data.pe()->sections();

	for (microsoft_pe_t::section_t* i : *sections)
	{
		// Check if each section is read only or executable
		bool is_executable = i->characteristics() & 0x20000000;  // Section is executable.
		bool is_read_only = i->characteristics() & 0x40000000;  // Section is readable.

		if (is_read_only)
			read_only_sections.push_back(i);

		if (is_executable)
			executable_sections.push_back(i);
	}

	if (read_only_sections.empty() || read_only_sections.empty())
	{
		printf("Error, failed to find any sections in the pe.\n");
		throw;
	}
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

		printf("\nNo command line arguments entered, please press any key to exit.\n");
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