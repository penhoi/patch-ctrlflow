#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "struct.h"

int main (int argc, char *argv[])
{
	if (argc != 3)  {
		printf("%s elf_file new_baseaddress\n", argv[0]);    
		return EXIT_FAILURE;
	}

	char *input_filename = argv[1];
	char output_filename[256];
	int idx = (!strncasecmp(argv[2], "0x", 2))?16:10;
	long baseaddr = strtol(argv[2], NULL, idx); 

	elf_t *elf = parse_elf_file (input_filename);
	Elf_Internal_Ehdr *ehdr = &elf->elf_header;

	if ((ehdr->e_type == ET_DYN) &&
			(ehdr->base_address < 0x20000)) {
		adjust_base_address(elf, 0x20000);
	}

	cfi_vma vma;
	size_t oft;
	Elf_Internal_Shdr *dumb = prelayout_dumb_section(elf);
	dumb->binary = strdup("test");
	dumb->sh_size = 5;
	insert_dumb_section(elf, dumb);

	stpcpy(stpcpy(output_filename, input_filename), "_");
	output_elf_object (elf, output_filename);


	return EXIT_SUCCESS;
}

