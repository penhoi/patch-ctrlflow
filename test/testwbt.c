#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "struct.h"

int mysprintf(void *dumb, const char *fmt, ...)
{		
	va_list args;
	size_t n;

	va_start(args, fmt);
	n = vprintf(fmt, args);
	va_end(args);
	return n;
}


/* Main Contains Menu */
int main(int argc, char* argv[])
{
	cfi_info_t info;
	info.alloc = 16;
	info.info = (toinfo_t*)malloc(info.alloc * sizeof(toinfo_t));
	info.fromvma = 0x8048000;
	/*
	   000000000804b83d 36
	   000000000804b857 37
	   000000000804b872 38
	   000000000804b88c 37
	   000000000804e235 52846
	   000000000804e267 56351
	   000000000804e4d8 47
	   000000000804e4f7 51
	   000000000804e517 55
	   000000000804e536 55
	   000000000804e7f8 16
	   */

	printf("Generate Weight Balanced Tree\n");          
	info.info[0].tovma = 0, info.info[0].freq = 0;
	info.info[1].tovma = 0xb83d, info.info[1].freq = 36;
	info.info[2].tovma = 0xb857, info.info[2].freq =  37;
	info.info[3].tovma = 0xb872, info.info[3].freq =  38;
	info.info[4].tovma = 0xb88c, info.info[4].freq =  37;
	info.info[5].tovma = 0xe235, info.info[5].freq =  52846;
	info.info[6].tovma = 0xe267, info.info[6].freq =  56351;
	info.info[7].tovma = 0xe4d8, info.info[7].freq =  47;
	info.info[8].tovma = 0xe4f7, info.info[8].freq =  51;
	info.info[9].tovma = 0xe517, info.info[9].freq =  55;
	info.info[10].tovma = 0xe536, info.info[10].freq =  55;
	info.info[11].tovma = 0xe7f8, info.info[11].freq =  16;
	info.pos = 12;


	asmcode_blk_t *sfile;
	sfile = explicitate_cfi (&info, NULL);
	if (sfile != NULL)
		printf("%s\n", sfile->buffer);

	return 0;
}
