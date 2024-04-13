#include "Dumper.h"

#include <fstream>

std::vector<microsoft_pe_t::section_t*> g_executable_sections;
std::vector<microsoft_pe_t::section_t*> g_read_only_sections;

microsoft_pe_t* g_data;

void Dumper::MSPE::get_executable_and_read_only_sections()
{
	// Get pe sections and iterate through them.
	std::vector<microsoft_pe_t::section_t*>* sections = g_data->pe()->sections();

	for (microsoft_pe_t::section_t* i : *sections)
	{
		// Check if each section is executable
		bool is_executable = i->characteristics() & 0x20000000;  // Section is executable.
		bool is_read_only = i->characteristics() & 0x40000000;  // Section is readable.

		if (is_executable)
			g_executable_sections.push_back(i);

		if (is_read_only)
			g_read_only_sections.push_back(i);
	}

	if (g_executable_sections.empty() || g_read_only_sections.empty())
	{
		printf("Error, failed to find any executable sections in the pe.\n");
		throw;
	}
}

void Dumper::MSPE::parse_sections_for_vtables()
{
	uintptr_t* SectionBuffer;
	size_t TotalSectionSize = 0;

	for (microsoft_pe_t::section_t* i : g_read_only_sections)
	{
		TotalSectionSize += i->size_of_raw_data();
	}

	for (microsoft_pe_t::section_t* i : g_executable_sections)
	{
		printf("Parsing %s Section for VTables.\n", i->name().c_str());

		size_t SectionSize = i->size_of_raw_data();
		size_t Max = SectionSize / sizeof(uintptr_t);

		for (size_t i = 0; i < Max; i++)
		{
			if (i == 0 || i + 1 > Max)
				continue;

			printf("Test: %llu\n", i);
		}
	}
}

void Dumper::MSPE::Dump(const char* binary_path)
{
	std::ifstream input(binary_path, std::ios::binary);

	kaitai::kstream ks(&input);

	g_data = new microsoft_pe_t(&ks);

	Dumper::MSPE::get_executable_and_read_only_sections();

	Dumper::MSPE::parse_sections_for_vtables();
}