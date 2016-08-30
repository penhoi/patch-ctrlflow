#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <libintl.h>
#include <errno.h>
#include <sys/stat.h>
#include <bfd.h>
#include <dis-asm.h>
#include "struct.h"

	int
main (int argc, char **argv)
{
	char *elf = argv[1];

	elf_asmcode_t *code = disasm_elf_file (elf, NULL, NULL);

	code->sprintf(code, NULL);

	return 0;
}
