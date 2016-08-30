#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <libintl.h>
#include <libgen.h>
#include <errno.h>
#include <sys/stat.h>
#include <assert.h>
#include <dis-asm.h>
#include <bfd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include "struct.h"


	static bool
add_cfi_info_node(void *elf_cfi_info, const void *cfi_info)
{
	assert((elf_cfi_info != NULL) && (cfi_info != NULL));
	elf_cfi_t *all = (elf_cfi_t*)elf_cfi_info;

	all->ar[all->pos++] = (cfi_info_t*)cfi_info;

	if (all->pos >= all->alloc) {
		all->alloc *= 2;
		all->ar = (cfi_info_t**)xrealloc(all->ar,
				all->alloc*sizeof(elf_cfi_t*));
	}

	return true;
}

	static cfi_info_t*
find_cfi_info_node(void *elf_cfi_info, const cfi_vma* fromvma)
{
	elf_cfi_t *all = (elf_cfi_t*)elf_cfi_info;
	cfi_info_t **ar = all->ar;
	int i;

	for (i = 0; i < all->pos; i++) {
		if (ar[i]->fromvma == *fromvma)
			return ar[i];
	}
	return NULL;
}

	static elf_cfi_t *
read_elf_cfi_info(const char *fname)
{
	FILE *f;

	f = fopen(fname, "r");
	if (NULL == f)
		return NULL;

	elf_cfi_t *elf_cfi = (elf_cfi_t*)
		xmalloc(sizeof(elf_cfi_t));
	elf_cfi->alloc = 100;
	elf_cfi->ar = (cfi_info_t**)xmalloc(
			elf_cfi->alloc * sizeof(cfi_info_t*));
	elf_cfi->pos = 0;
	elf_cfi->add_node  = (add_ft)add_cfi_info_node;
	elf_cfi->find_node = (find_ft)find_cfi_info_node;

	char *line = (char*)xmalloc(256);
	size_t len = 256;
	ssize_t read;

	while((read = getline(&line, &len, f)) != EOF) {
		char *freq, *from, *to;
		cfi_vma fromvma, tovma;
		size_t nfreq;

		if (!isxdigit(line[0]))
			continue;

		//get string of each field
		freq = line;
		from = strstr(line, "0x");
		if (from != NULL)
			to = strstr(from+2, "0x");
		if ((freq == NULL) || (from==NULL) || (to == NULL)) {
			perror("Unexpected data format");
			exit(EXIT_FAILURE);
		}

		//convert strings to data
		nfreq = strtol(freq, NULL, 10);
		fromvma = strtol(from, NULL, 16);
		tovma = strtol(to, NULL, 16);
		if ((nfreq == 0) || (fromvma == 0) || (tovma == 0)) {
			perror("Unexpected data: mixed with 0");
			exit(EXIT_FAILURE);
		}

		//allocate or enlarge cfi_info_t nodes if necessary;
		cfi_info_t *node = elf_cfi->find_node(
				elf_cfi, &fromvma);
		if (node == NULL) {
			node = (cfi_info_t*)xmalloc(sizeof(cfi_info_t));
			node->alloc = 10;
			node->info = (toinfo_t*)calloc(
					node->alloc, sizeof(toinfo_t));
			node->pos = 0;
			node->fromvma = fromvma;
			elf_cfi->add_node(elf_cfi, node);
		}

		//store cfi information
		toinfo_t *toinfo;
		int i;
		for( i = 0, toinfo = node->info; i< node->pos; i++) {
			if (toinfo[i].tovma == tovma) {
				perror("Unexpected data: too many occurences");
				exit(EXIT_FAILURE);
			}
		}
		toinfo[i].tovma = tovma;
		toinfo[i].freq = nfreq;

		node->pos++;
		if (node->pos >= node->alloc) {
			node->alloc *= 2;
			node->info = (toinfo_t*)xrealloc(node->info,
					node->alloc * sizeof(toinfo_t));
		}
	}
	return elf_cfi;
}

	static bool 
patch_asmcode_block(elf_asmcode_t *code, cfi_vma vma, const asmcode_blk_t *patch)
{
	asmcode_blk_t **ar = code->ar;
	asmcode_blk_t *oldblk;
	bool bFind = false;
	int i;

	for (i = 0; i< code->pos; i++) {
		if ((ar[i]->startvma <= vma) && 
				(vma < ar[i]->endvma)) {
			bFind = true;
			break;
		}
	}
	if (!bFind)
		return false;
	else
		oldblk = ar[i];

	//split current blk into three parts;
	char *ptr = oldblk->buffer;
	bool bSplit = false;
#define GLAB "glab_"
#define GLABLEN (sizeof(GLAB)-1)
#define NGLAB "\nglab_"
	while (ptr && (ptr < oldblk->buffer + oldblk->pos)) {
		cfi_vma addr;

		ptr = strstr(ptr, GLAB);
		if (NULL == ptr) 
			break;

		addr = strtol(ptr+GLABLEN, NULL, 16);
		if (addr == vma) {
			bSplit = true;
			break;
		}
		else {
			ptr = strstr(ptr+GLABLEN, NGLAB)+1;
		}
	}
	if (!bSplit || (ptr == NULL))
		return false;

	char *head, *midasm, *tail;
	head = ptr;
	midasm = strpbrk(ptr, "cjr");
	tail = strstr(ptr, NGLAB) + 1;
	if (midasm == NULL) 
		return false;

	//generate the patched asmcode block.
	asmcode_blk_t *newblk = (asmcode_blk_t*)xmalloc(sizeof(asmcode_blk_t));
	memcpy(newblk, oldblk, sizeof(asmcode_blk_t));
	newblk->type = CT_BEPATCH;
	newblk->alloc = oldblk->pos + patch->pos + 120;
	newblk->buffer = (char*)xmalloc(newblk->alloc);
	ptr = stpncpy(newblk->buffer, oldblk->buffer, head-oldblk->buffer);
	ptr = stpcpy(ptr, patch->buffer);
	//fix me
	//if (call) {}
	//else if (jmp) {}
	//else {}
	ptr = stpncpy(ptr, midasm, tail-midasm);
	ptr = stpcpy(ptr, tail);
	newblk->pos = ptr-newblk->buffer;

	//hook the original code
	oldblk->pos = 0;
	oldblk->sprintf(oldblk, "\tjmp    glab_%08x\n", oldblk->startvma);

	code->add_block(code, newblk);

	return true;
}

extern int ATTRIBUTE_PRINTF_2
objdump_sprintf (asmcode_blk_t *f, const char *format, ...);

	static int
asmcode_blk_cmp_fn(const void *a, const void *b)
{
	asmcode_blk_t *blka = *(asmcode_blk_t**)a;
	asmcode_blk_t *blkb = *(asmcode_blk_t**)b;
	int ret =  (blkb->type == CT_BEPATCH) - (blka->type == CT_BEPATCH);

	return (ret != 0)?ret:
		((blka->startvma > blkb->startvma) - (blka->startvma < blkb->startvma));
}

	static bool
patch_elf_asmcode(elf_asmcode_t *code, elf_cfi_t *info)
{
	asmcode_blk_t *patch = (asmcode_blk_t*)xmalloc(sizeof(asmcode_blk_t));
	patch->alloc = 10 * 4 * 15;
	patch->buffer = (char*)xmalloc(patch->alloc);
	patch->sprintf = (sprintf_ft) objdump_sprintf;

	cfi_info_t **ar = info->ar;
	int i;

	for (i = 0; i < info->pos; i++) {
		patch->pos = 0;
		explicitate_cfi (ar[i], &patch);
		patch->startvma = ar[i]->fromvma;
		if (!patch_asmcode_block(code, patch->startvma, patch)) {
			perror("Unexpected asmcode block format");
			exit(EXIT_FAILURE);
		}
	}
	qsort(code->ar, code->pos, 
			sizeof(asmcode_blk_t*), asmcode_blk_cmp_fn);
	return true;
}

	static bool
patch_current_blk_p(elf_cfi_t *cfi, asmcode_blk_t *blk)
{
	if ((cfi == NULL) || (blk == NULL))
		return false;

	cfi_info_t **ar = cfi->ar;
	int i;

	for (i = 0; i < cfi->pos; i++) {
		if ((blk->startvma <= ar[i]->fromvma) && 
				(ar[i]->fromvma < blk->endvma))
			return true;
	}
	return false;
}


#define STARTLB "startpatch"
#define ENDLB "endpatch"
	static size_t 
get_elf_patch_size (elf_asmcode_t *code)
{
	char sfile[256] = {"xxxtmp.s"};
	char ofile[256] = {"xxxtmp.o"};
	char cmd[256], *tmp;

	snprintf(cmd, 256, "as --32 -o %s %s", ofile, sfile);

	//print out assembly code of the patch.
	FILE *fs = fopen(sfile, "w+");
	if (fs == NULL) 
		return 0;

	fprintf(fs, "%s:\n", STARTLB);

	asmcode_blk_t **ar = code->ar;
	int i;

	for (i = 0; i<code->pos; i++) {
		if (ar[i]->type == CT_BEPATCH) {
			fprintf(fs, "\t.align  4\n");
			fprintf(fs, "%s\n", ar[i]->buffer);
		}
	}

	fprintf(fs, "%s:\n", ENDLB);
	fclose(fs);

	//Compile the patch
	int gccret = system(cmd);
	if (gccret == -1) 
		return 0;

	//Figures out the code size for patching.
	bfd_init();

	bfd *abfd  = bfd_openr(ofile, NULL);
	if (NULL == abfd)
		return 0;

	char **matching;
	cfi_vma startlb, endlb;
	int nmatch;

	if (bfd_check_format_matches(abfd, bfd_object, &matching)) {
		long storage = bfd_get_symtab_upper_bound(abfd);
		asymbol **sym = (asymbol**)xmalloc(storage);
		int symcount = bfd_canonicalize_symtab(abfd, sym);

		nmatch = 0;
		for (i = 0; ((i< symcount) && (nmatch < 2)); i++) {
			const char* name = bfd_asymbol_name(sym[i]);
			if (!strcmp(name, STARTLB)) {
				startlb = bfd_asymbol_value(sym[i]);
				nmatch++;
			}
			else if (!strcmp(name, ENDLB)) {
				endlb = bfd_asymbol_value(sym[i]);
				nmatch++;
			}
		}
	}

	if(nmatch != 2) 
		return 0;

	bfd_close(abfd);			

	//delete temporary files;
	remove (sfile);
	remove (ofile);

	return (endlb-startlb);
}

	static bool
generate_object_for_patching (elf_asmcode_t *code, const char*obj_file, cfi_vma patch_start)
{
	char sfile[256], cmd[256], *tmp;

	stpcpy(stpcpy(sfile, obj_file), ".s");
	snprintf(cmd, 256, "as --32 -o %s %s", obj_file, sfile);

	FILE *fs = fopen(sfile, "w+");
	if (fs == NULL) {
		perror("Open temporary file failed!\n");
		return false;
	}

	fprintf(fs, "\t.org 0x%lx\n", patch_start);

	asmcode_blk_t **ar = code->ar;
	int i;

	for (i = 0; i< code->pos; i++) {
		if (ar[i]->type == CT_BEPATCH) {
			fprintf(fs, "\t.align  4\n");
			fprintf(fs, "%s\n", ar[i]->buffer);
		}
		else if (ar[i]->type != CT_BEPATCH) {
			fprintf(fs, "\t.org 0x%lx\n", ar[i]->startvma);
			fprintf(fs, "%s\n", ar[i]->buffer);
		}
	}

	fclose(fs);

	int gccret = system(cmd);
	if (gccret == -1) {
		perror("Compile temporary file failed!\n");
		return false;
	}
	else
		return true;
}

void Usage(char *prog)
{
	printf("%s --cfi info_file elf_file", prog);
}

/* Main Contains Menu */
int main(int argc, char* argv[])
{
	char elf_file[256];
	char info_file[256];
	bool cfi_explicitation = false;

	//parse options
	while (1) {
		int c, ind, cfi;
		static struct option long_opt[] = {
			{"cfi", required_argument, 0, 'p'},
		};

		c = getopt_long(argc, argv, "", long_opt, &ind);
		if (c == -1)
			break;

		switch(c) {
			case 'p': 
				cfi_explicitation = true;
				if (optarg != NULL)
					strncpy(info_file, optarg, 256);
				break;
			default:
				break;
		}
	}
	if ((!cfi_explicitation) || (optind != argc -1)) {
		Usage(argv[0]);
		return EXIT_FAILURE;
	}
	strncpy(elf_file, argv[optind], 256);

	// read control-flow infomation
	elf_cfi_t *cfi = read_elf_cfi_info(info_file);
	if (cfi == NULL) {
		perror("Read control flow information failed!\n");
		return EXIT_FAILURE;
	}

	//parse && disasm elf file
	elf_t *elf = parse_elf_file(elf_file);
	if (elf == NULL) {
		perror("Parse elf file failed!\n");
		return EXIT_FAILURE;
	}

	elf_asmcode_t *code = disasm_elf_file (elf_file, 
			(checker_ft)patch_current_blk_p, cfi);
	if (code == NULL) {
		perror("Disassemble elf file failed!\n");
		return EXIT_FAILURE;
	}

	if (!patch_elf_asmcode(code, cfi)) {
		perror("Patch elf asmcode failed!\n");
		return EXIT_FAILURE;
	}


	//create obj file for binary-level patching.
	char obj_file[256];
	Elf_Internal_Shdr *dumb;
	size_t patch_size, patch_size_align;
	cfi_vma ba;

	char *tmp = dirname(strdup(elf_file));
	stpcpy(stpcpy(obj_file, tmp), "/cfi-patch.o");
free(tmp);

	patch_size = get_elf_patch_size(code);
	patch_size_align = (patch_size + PAGE_SIZE - 1) & -PAGE_SIZE;
	ba = elf->elf_header.base_address;

	//if SO files always have base address 0;
	if (ba < patch_size) {
		adjust_base_address(elf, ba+patch_size);
	}
	dumb = prelayout_dumb_section(elf);

	generate_object_for_patching(code, obj_file, dumb->sh_addr - patch_size_align);

	//start patching
	elf_t *obj = parse_elf_file(obj_file);
	if (obj == NULL) {
		perror("Parse patch file failed!\n");
		return EXIT_FAILURE;
	}

	char *objtext;
	int i;

	i = 0;
	while (obj->section_headers[i].sh_type != SHT_PROGBITS) i++;
	objtext = obj->section_headers[i].binary;

	char *patch = objtext + dumb->sh_addr - patch_size_align;
	dumb->sh_size = patch_size_align;
	dumb->binary = patch;
	insert_dumb_section(elf, dumb);

	asmcode_blk_t **ar = code->ar;
	for (i = 0; i < code->pos; i++) {
		if (ar[i]->type == CT_NEEDPATCH) {
			patch = objtext + ar[i]->startvma;
			patch_section_data(elf, ar[i]->startvma, patch, 5);
		}
	}

	char elf_out[256];
	stpcpy(stpcpy(elf_out, elf_file), "_");
	output_elf_object(elf, elf_out);

	return EXIT_SUCCESS;
}
