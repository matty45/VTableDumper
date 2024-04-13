#pragma once
#include "parsers/microsoft_pe/microsoft_pe.h"

class Dumper
{
public:
	class MSPE
	{
	public:

		static void get_executable_and_read_only_sections();
		static void parse_sections_for_vtables();
		static void Dump(const char* binary_path);
	};
};
