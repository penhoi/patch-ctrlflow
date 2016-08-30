#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <alloca.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <bfd.h>
#include <ctype.h>
#include <stdarg.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <bfd.h>
#include <dis-asm.h>
#include "struct.h"

#include "struct.h"

#define _(string) gettext(string)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &(((TYPE *) 0)->MEMBER))
#endif

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))


/* Retrieve NMEMB structures, each SIZE bytes long from FILE starting at OFFSET.
   Put the retrieved data into VAR, if it is not NULL.  Otherwise allocate a buffer
   using malloc and fill that.  In either case return the pointer to the start of
   the retrieved data or NULL if something went wrong.  If something does go wrong
   emit an error message using REASON as part of the context.  */

/* Return a pointer to a section containing ADDR, or NULL if no such
   section exists.  */

static void* xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL) {
		perror("Out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

static void* xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (p == NULL) {
		perror("Out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

static void* xcalloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (p == NULL) {
		perror("Out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}


	static bool
get_32bit_program_headers (elf_t *obj, int fd, Elf_Internal_Phdr * pheaders)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Phdr *   internal;
	Elf32_Phdr * phdrs;
	Elf32_Phdr * external;
	bool ld; //PT_LOAD section
	int i;

	phdrs = (Elf32_Phdr*)xcalloc(ehdr->e_phnum, ehdr->e_phentsize);
	if (phdrs == NULL)  
		return false;

	if (pread(fd, phdrs, ehdr->e_phentsize * ehdr->e_phnum, ehdr->e_phoff) < 0) 
		goto freebuf;

	ld = false;
	for (i = 0, internal = pheaders, external = phdrs;
			i < ehdr->e_phnum;
			i++, internal++, external++) {
		internal->p_type   = external->p_type;
		internal->p_offset = external->p_offset;
		internal->p_vaddr  = external->p_vaddr;
		internal->p_paddr  = external->p_paddr;
		internal->p_filesz = external->p_filesz;
		internal->p_memsz  = external->p_memsz;
		internal->p_flags  = external->p_flags;
		internal->p_align  = external->p_align;
		if ((internal->p_type == PT_LOAD) && (!ld)) {
			ld = true;
			ehdr->base_address = internal->p_vaddr;
		}
	}

	ehdr->phdrs = (char*)phdrs;
	return true;

freebuf:
	free (phdrs);
	return false;
}

	static bool
get_64bit_program_headers (elf_t *obj, int fd, Elf_Internal_Phdr * pheaders)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Phdr *   internal;
	Elf64_Phdr * phdrs;
	Elf64_Phdr * external;
	bool ld;	//PT_LOAD section
	unsigned int i;

	phdrs = (Elf64_Phdr*)xcalloc(ehdr->e_phnum, ehdr->e_phentsize);
	if (phdrs == NULL) 
		return false;

	if (pread(fd, phdrs, ehdr->e_phentsize * ehdr->e_phnum, ehdr->e_phoff) < 0) 
		goto freebuf;

	ld = false;
	for (i = 0, internal = pheaders, external = phdrs;
			i < ehdr->e_phnum;
			i++, internal++, external++) {
		internal->p_type   = external->p_type;
		internal->p_flags  = external->p_flags;
		internal->p_offset = external->p_offset;
		internal->p_vaddr  = external->p_vaddr;
		internal->p_paddr  = external->p_paddr;
		internal->p_filesz = external->p_filesz;
		internal->p_memsz  = external->p_memsz;
		internal->p_align  = external->p_align;
		if ((internal->p_type == PT_LOAD) && (!ld)) {
			ld = true;
			ehdr->base_address = internal->p_vaddr;
		}
	}
	ehdr->phdrs = (char*)phdrs;
	return true;

freebuf:
	free (phdrs);
	return false;
}

/* Returns 1 if the program headers were read into `program_headers'.  */
	static bool
get_program_headers (elf_t *obj, int fd)
{
	Elf_Internal_Ehdr * ehdr = &obj->elf_header;
	Elf_Internal_Phdr * phdrs;
	bool suc; //successfully get program headers.

	if (ehdr->e_phnum == 0)
		return false;

	/* don't read again.  */
	if (obj->program_headers != NULL)
		return false;

	phdrs = (Elf_Internal_Phdr *) xcalloc (ehdr->e_phnum,
			sizeof (Elf_Internal_Phdr));
	if (phdrs == NULL)
		return false;

	suc = (obj->is_32bit
			? get_32bit_program_headers (obj, fd, phdrs)
			: get_64bit_program_headers (obj, fd, phdrs));
	if (!suc)
		goto freebuf;

	obj->program_headers = phdrs;
	return true;

freebuf:
	free(phdrs);
	return false;
}

	static void
assert_elf_file_modifiable(elf_t *obj)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Phdr *phdrs = obj->program_headers;
	bool mod = false; //modifiable
	bool dyn = false; //has PT_DYNAMIC section
	int i;

	if (ehdr->e_phnum < 3)
		goto warnexit;

	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdrs[i].p_type == PT_DYNAMIC) {
			dyn = true;
			break;
		}
	}

	if (ehdr->e_type == ET_EXEC) {
		//dynamically linked exe
		if (dyn) {
			mod = (phdrs[0].p_type == PT_PHDR) &&
				(phdrs[1].p_type == PT_INTERP) &&
				(phdrs[2].p_type == PT_LOAD);
		}
		//statically linked exe
		else {
			mod = (phdrs[0].p_type == PT_LOAD) &&
				(phdrs[1].p_type == PT_LOAD);
		}
	} 
	else if (ehdr->e_type == ET_DYN) {
		//Shared objects are always dynamically linked.
		mod = dyn &&
			(phdrs[0].p_type == PT_LOAD) &&
			(phdrs[1].p_type == PT_LOAD);
	}

	if (mod)
		return;

warnexit:
	fprintf(stderr, "Cannot modify this file!\n");
	exit(EXIT_SUCCESS);
}

	static bool
get_32bit_section_headers (elf_t *obj, int fd, unsigned int num)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *   internal;
	Elf32_Shdr * shdrs;
	unsigned int i;

	shdrs = (Elf32_Shdr*)xcalloc(ehdr->e_shnum, ehdr->e_shentsize);
	if (shdrs == NULL) 
		return false;
	if (pread(fd, shdrs, ehdr->e_shentsize * ehdr->e_shnum, ehdr->e_shoff) < 0) 
		return false;

	obj->section_headers = (Elf_Internal_Shdr *) xcalloc (num,
			sizeof (Elf_Internal_Shdr));

	if (obj->section_headers == NULL)
		return false;

	for (i = 0, internal = obj->section_headers;
			i < num; i++, internal++) {
		internal->sh_name      = shdrs[i].sh_name;
		internal->sh_type      = shdrs[i].sh_type;
		internal->sh_flags     = shdrs[i].sh_flags;
		internal->sh_addr      = shdrs[i].sh_addr;
		internal->sh_offset    = shdrs[i].sh_offset;
		internal->sh_size      = shdrs[i].sh_size;
		internal->sh_link      = shdrs[i].sh_link;
		internal->sh_info      = shdrs[i].sh_info;
		internal->sh_addralign = shdrs[i].sh_addralign;
		internal->sh_entsize   = shdrs[i].sh_entsize;
	}

	ehdr->shdrs = (char*)shdrs;

	return true;
}

	static bool
get_64bit_section_headers (elf_t *obj, int fd, unsigned int num)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *   internal;
	Elf64_Shdr * shdrs;
	unsigned int i;

	shdrs = (Elf64_Shdr*)xcalloc(ehdr->e_shnum, ehdr->e_shentsize);
	if (shdrs == NULL) 
		return false;
	if (pread(fd, shdrs, ehdr->e_shentsize * ehdr->e_shnum, ehdr->e_shoff) < 0) 
		return false;

	obj->section_headers = (Elf_Internal_Shdr *) xcalloc (num,
			sizeof (Elf_Internal_Shdr));

	if (obj->section_headers == NULL)
		return false;

	for (i = 0, internal = obj->section_headers;
			i < num; i++, internal++) {
		internal->sh_name      = shdrs[i].sh_name;
		internal->sh_type      = shdrs[i].sh_type;
		internal->sh_flags     = shdrs[i].sh_flags;
		internal->sh_addr      = shdrs[i].sh_addr;
		internal->sh_size      = shdrs[i].sh_size;
		internal->sh_entsize   = shdrs[i].sh_entsize;
		internal->sh_link      = shdrs[i].sh_link;
		internal->sh_info      = shdrs[i].sh_info;
		internal->sh_offset    = shdrs[i].sh_offset;
		internal->sh_addralign = shdrs[i].sh_addralign;
	}

	ehdr->shdrs = (char*)shdrs;

	return true;
}

	static bool
get_section_headers (elf_t *obj, int fd)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	bool suc = false;

	obj->section_headers = NULL;
	if (ehdr->e_shnum == 0) 
		return false;

	if (obj->is_32bit)
		suc = get_32bit_section_headers (obj, fd, ehdr->e_shnum);
	else
		suc = get_64bit_section_headers (obj, fd, ehdr->e_shnum);
	if (!suc)
		return false;

	// get sections' binary content
	Elf_Internal_Shdr * shdr = obj->section_headers;
	char *buf;
	int nb;
	int i;

	/* Scan the sections for the dynamic symbol table
	   and dynamic string table and debug sections.  */
	for (i = 0;	i < ehdr->e_shnum; i++, shdr++) {
		nb = shdr->sh_size;
		buf = (char*)xmalloc(nb);
		if (buf == NULL) {
			i--;
			goto reverse;
		}
		if (pread(fd, buf, nb, shdr->sh_offset) < 0)
			goto reverse;

		shdr->binary = buf;
	}

	return true;

reverse:
	while (i >= 0) {
		free(shdr->binary);
		shdr->binary = NULL;
		i--;
	}
	return false;
}

	static bool
get_file_header (elf_t *obj, int fd)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;

	/* Read in the identity array.  */
	if (pread (fd, ehdr->e_ident, EI_NIDENT, 0) < 0)
		return false;

	/* For now we only support 32 bit and 64 bit ELF files.  */
	obj->is_32bit = (ehdr->e_ident[EI_CLASS] != ELFCLASS64);

	/* Read in the rest of the header.  */
	if (obj->is_32bit)
	{
		Elf32_Ehdr ehdr32;

		if (pread (fd, &ehdr32.e_type, sizeof (ehdr32) - EI_NIDENT, EI_NIDENT) < 0)
			return false;

		ehdr->e_type      = ehdr32.e_type;
		ehdr->e_machine   = ehdr32.e_machine;
		ehdr->e_version   = ehdr32.e_version;
		ehdr->e_entry     = ehdr32.e_entry;
		ehdr->e_phoff     = ehdr32.e_phoff;
		ehdr->e_shoff     = ehdr32.e_shoff;
		ehdr->e_flags     = ehdr32.e_flags;
		ehdr->e_ehsize    = ehdr32.e_ehsize;
		ehdr->e_phentsize = ehdr32.e_phentsize;
		ehdr->e_phnum     = ehdr32.e_phnum;
		ehdr->e_shentsize = ehdr32.e_shentsize;
		ehdr->e_shnum     = ehdr32.e_shnum;
		ehdr->e_shstrndx  = ehdr32.e_shstrndx;
	}
	else
	{
		Elf64_Ehdr ehdr64;

		if (pread (fd, &ehdr64.e_type, sizeof (ehdr64) - EI_NIDENT, EI_NIDENT) < 0)
			return false;

		ehdr->e_type      = ehdr64.e_type;
		ehdr->e_machine   = ehdr64.e_machine;
		ehdr->e_version   = ehdr64.e_version;
		ehdr->e_entry     = ehdr64.e_entry;
		ehdr->e_phoff     = ehdr64.e_phoff;
		ehdr->e_shoff     = ehdr64.e_shoff;
		ehdr->e_flags     = ehdr64.e_flags;
		ehdr->e_ehsize    = ehdr64.e_ehsize;
		ehdr->e_phentsize = ehdr64.e_phentsize;
		ehdr->e_phnum     = ehdr64.e_phnum;
		ehdr->e_shentsize = ehdr64.e_shentsize;
		ehdr->e_shnum     = ehdr64.e_shnum;
		ehdr->e_shstrndx  = ehdr64.e_shstrndx;
	}

	char *buf = (char*)xmalloc(ehdr->e_ehsize);
	int nb = ehdr->e_ehsize;

	if (pread(fd, buf, nb, 0) < 0) {
		free(buf);
		return false;
	}
	else {
		ehdr->ehdr = buf;
		return true;
	}
}

/* Process one ELF object file according to the command line options.
   This file may actually be stored in an archive.  The file is
   positioned at the start of the ELF object.  */
	static bool
parse_elf_object (elf_t *obj, FILE * file)
{
	int fd = fileno(file);

	if (! get_file_header (obj, fd)) {
		perror ("Failed to read file header");
		return false;
	}

	if (! get_section_headers (obj, fd)) {
		perror ("Failed to parse section headers");
		return false;
	}

	if (obj->elf_header.e_type != ET_REL) {
		if (! get_program_headers (obj, fd)) {
			perror ("Failed to parse program headers");
			return false;
		}
		assert_elf_file_modifiable(obj);
	}

	return true;
}

	EXPORT	elf_t *
parse_elf_file (char * elf_file)
{
	FILE * fd;
	struct stat statbuf;
	char armag[EI_NIDENT+4];
	bool ret;

	if (stat (elf_file, &statbuf) < 0) 
		return NULL;

	if (! S_ISREG (statbuf.st_mode)) 
		return NULL;

	fd = fopen (elf_file, "rb");
	if (fd == NULL) 
		return NULL;

	if (fread (armag, EI_NIDENT, 1, fd) != 1) {
		fclose (fd);
		return NULL;
	}

	rewind (fd);

	elf_t *obj = (elf_t*)xmalloc(sizeof(elf_t));
	obj->file = strdup(elf_file);

	ret = parse_elf_object (obj, fd);
	if (!ret) {
		perror("parse elf object failed");
		free(obj);
		return NULL;
	}

	fclose (fd);

	return obj;
}

	static bool
_correct_elf32_initarray(elf_t *obj, int diff)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *shdr = obj->section_headers;
	Elf32_Addr *ptr = NULL;
	int ne, i;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++){
		if (shdr->sh_addr == obj->dynamic_info[DT_INIT_ARRAY]) {
			ptr = (Elf32_Addr*)shdr->binary;
			ne = shdr->sh_size/sizeof(Elf32_Addr);
			break;
		}
	}
	if (ptr == NULL)
		return false;

	for (i =0; i<ne; i++, ptr++)
		*ptr += diff;

	return true;
}

	static bool
_correct_elf32_finiarray(elf_t *obj, int diff)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *shdr = obj->section_headers;
	Elf32_Addr *ptr = NULL;
	int ne, i;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++){
		if (shdr->sh_addr == obj->dynamic_info[DT_FINI_ARRAY]) {
			ptr = (Elf32_Addr*)shdr->binary;
			ne = shdr->sh_size/sizeof(Elf32_Addr);
			break;
		}
	}
	if (ptr == NULL)
		return false;

	for (i =0; i<ne; i++, ptr++)
		*ptr += diff;

	return true;
}

	static bool
_correct_elf32_gotarray(elf_t* obj, int diff)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *shdr = obj->section_headers;
	Elf32_Addr *ptr = NULL;
	int ne, i;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++){
		if (shdr->sh_addr == obj->dynamic_info[DT_PLTGOT]) {
			ptr = (Elf32_Addr*)shdr->binary;
			ne = shdr->sh_size/sizeof(Elf32_Addr);
			break;
		}
	}
	if (ptr == NULL)
		return false;

	ptr[0] += diff;
	for (i =3; i<ne; i++)
		ptr[i] += diff;

	return true;
}

	static bool
_correct_elf32_dynamic_section(char *start, int nbytes, int diff)
{
	Elf32_Dyn *ent = (Elf32_Dyn*)start;
	bool bptr;

	while (ent->d_tag != DT_NULL) {
		if (ent->d_tag > DT_ENCODING) {
			switch(ent->d_tag) {
				case DT_GNU_HASH:
					ent->d_un.d_ptr += diff;
					break;
				case DT_VERDEF:
					ent->d_un.d_ptr += diff;
					break;
				case DT_VERDEFNUM:
					break;
				case DT_VERNEED:
					ent->d_un.d_ptr += diff;
					break;
				case DT_VERNEEDNUM:
					break;
				case DT_VERSYM:
					ent->d_un.d_ptr += diff;
					break;
			}
		}
		else {
			bptr = false;
			switch(ent->d_tag) {
				case DT_NULL: break;
				case DT_NEEDED: break;
				case DT_PLTRELSZ: break;
				case DT_PLTGOT: 
								  bptr = true;
								  break;
				case DT_HASH: 
								  bptr = true;
								  break;
				case DT_STRTAB:
								  bptr = true;
								  break;
				case DT_SYMTAB: 
								  bptr = true;
								  break;
				case DT_RELA: 
								  bptr = true;
								  break;
				case DT_INIT: 
								  bptr = true;
								  break;
				case DT_FINI: 
								  bptr = true;
								  break;
				case DT_SONAME: break;
				case DT_RPATH: break;
				case DT_SYMBOLIC: break;
				case DT_REL: 
								  bptr = true;
								  break;
				case DT_RELSZ: break;
				case DT_RELENT: break;
				case DT_PLTREL: break;
				case DT_DEBUG: 
								bptr = true;
								break;
				case DT_TEXTREL:  break;
				case DT_JMPREL: 
								  bptr = true;
								  break;
				case DT_BIND_NOW: break;
				case DT_INIT_ARRAY: 
								  bptr = true;
								  break;
				case DT_FINI_ARRAY: 
								  bptr = true;
								  break;
				case DT_RUNPATH:  break;
				case DT_FLAGS: break;
				case DT_GNU_HASH:
							   bptr = true;
							   break;
				case DT_VERNEED: 
							   bptr = true;
							   break;
				case DT_VERSYM:
							   bptr = true;
							   break;
				default: break;
			}
			if (bptr) 
				ent->d_un.d_ptr += diff;
		}
		ent++;
	}

	return true;
}

	static bool
parse_elf32_dynamic_section(elf_t *obj, const char *start, int nbytes)
{
	Elf32_Dyn *ent = (Elf32_Dyn*)start;

	while (ent->d_tag != DT_NULL) {
		if (ent->d_tag < DT_ENCODING)
			obj->dynamic_info[ent->d_tag] = ent->d_un.d_ptr;
		ent++;
	}

	return true;
}


	static bool
_correct_elf32_symbol_section(char* start, int nbytes, int diff)
{
	Elf32_Sym *sym = (Elf32_Sym*)start;
	int nEnt = nbytes / sizeof(Elf32_Sym);
	int i;

	for (i = 0; i< nEnt; i++, sym++) {
		if ((sym->st_shndx != SHN_UNDEF) &&
				(sym->st_shndx != SHN_ABS)	&&
				(sym->st_shndx != SHN_COMMON)) {
			sym->st_value += diff;	   
		}	   
	}
	return true;
}

	static bool
_correct_elf32_rel_section(char* start, int nbytes, int diff)
{
	Elf32_Rel *rel = (Elf32_Rel*)start;
	int nEnt = nbytes / sizeof(Elf32_Rel);
	int i;

	for (i = 0; i< nEnt; i++, rel++) {
		rel->r_offset += diff;
	}	   
	return true;
}

	static bool
_correct_elf32_rela_section(char* start, int nbytes, int diff)
{
	Elf32_Rela *rel = (Elf32_Rela*)start;
	int nEnt = nbytes / sizeof(Elf32_Rela);
	int i;

	for (i = 0; i< nEnt; i++, rel++) {
		rel->r_offset += diff;
	}	   
	return true;
}

	static int
adjust_elf32_binary_for_updating_baseaddress (elf_t *obj, int diff)
{
	Elf_Internal_Ehdr *iehdr = &obj->elf_header;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)iehdr->ehdr;
	ehdr->e_entry += diff;
	int i;

	Elf_Internal_Shdr *ishdr = obj->section_headers;
	Elf32_Shdr *shdr = (Elf32_Shdr*)iehdr->shdrs;
	for (i = 0; i < ehdr->e_shnum; i++, shdr++, ishdr++) {
		if (shdr->sh_type == SHT_NULL)
			continue;
		else if (shdr->sh_addr != 0)
			shdr->sh_addr += diff;

		switch (shdr->sh_type) {
			case SHT_DYNAMIC: {
								  _correct_elf32_dynamic_section(ishdr->binary, 
										  ishdr->sh_size, diff);
								  parse_elf32_dynamic_section(obj, 
										  ishdr->binary, ishdr->sh_size);
								  break;
							  }
			case SHT_DYNSYM:
			case SHT_SYMTAB: {
								 _correct_elf32_symbol_section(ishdr->binary,
										 ishdr->sh_size, diff);
								 break;
							 }
			case SHT_REL: {
							  _correct_elf32_rel_section(ishdr->binary, 
									  ishdr->sh_size, diff);
							  break;
						  }
			case SHT_RELA: {
							   _correct_elf32_rela_section(ishdr->binary, 
									   ishdr->sh_size, diff);
							   break;
						   }
		}
	}

	Elf32_Phdr *phdr = (Elf32_Phdr*)iehdr->phdrs;
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_GNU_STACK) {
			continue;
		}
		if ((phdr->p_type != PT_LOAD) && (phdr->p_vaddr == 0)) {
			continue;
		}

		phdr->p_vaddr += diff;
		phdr->p_paddr += diff;
	}


	if (obj->dynamic_info[DT_INIT_ARRAY] != 0)
		_correct_elf32_initarray(obj, diff);

	if (obj->dynamic_info[DT_FINI_ARRAY] != 0)
		_correct_elf32_finiarray(obj, diff);

	if (obj->dynamic_info[DT_PLTGOT] != 0)
		_correct_elf32_gotarray(obj, diff);

	return true;
}

	EXPORT	bool
adjust_base_address(elf_t *obj, long new_ba)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	long org_ba, diff;
	int i;

	org_ba = ehdr->base_address;
	diff = new_ba - org_ba;

	//Adjust internal structures
	Elf_Internal_Phdr *phdr = obj->program_headers;
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_GNU_STACK) {
			continue;
		}
		else if ((phdr->p_vaddr == 0) &&
				(phdr->p_type != PT_LOAD)) {
			continue;
		}
		else {
			phdr->p_vaddr += diff;
			phdr->p_paddr += diff;
		}
	}

	Elf_Internal_Shdr *shdr = obj->section_headers;
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_NULL)
			continue;
		else if (shdr->sh_addr != 0)
			shdr->sh_addr += diff;
	}

	ehdr->e_entry += diff;

	//modify the binay content of each section
	if (obj->is_32bit) 
		return adjust_elf32_binary_for_updating_baseaddress (obj, (int)diff);

	return false;
}

//Dumb section only presented in internal structure (i.e. section_headers)
#define SHT_DUMB 20
	Elf_Internal_Shdr *
prelayout_dumb_section (const elf_t *obj)
{
	const Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	const Elf_Internal_Phdr *phdrs = obj->program_headers;
	const Elf_Internal_Shdr *shdrs = obj->section_headers;
	const Elf_Internal_Shdr *next = NULL;
	Elf_Internal_Shdr *dumb = NULL;

	//Insert a new dumb section after the SHT_NULL section if this is an SO, 
	//or after the .interp section if it is an EXE.
	if (ehdr->e_type == ET_EXEC) { 
		if (phdrs[0].p_type == PT_LOAD) 
			next = &shdrs[1];
		else 
			next = &shdrs[2];
	}
	else if (ehdr->e_type == ET_DYN) {
		next = &shdrs[1];
	}

	if (next != NULL) {
		dumb = (Elf_Internal_Shdr*)xcalloc(1, sizeof(Elf_Internal_Shdr));
		dumb->sh_type = SHT_DUMB;
		dumb->sh_addr = next->sh_addr;
		dumb->sh_offset = next->sh_offset;
	}
	return dumb;
}

	static bool
adjust_elf32_binary_for_dumb_section(elf_t *obj, int offset, int bytes)
{
	Elf_Internal_Ehdr  *iehdr = &obj->elf_header;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)iehdr->ehdr;

	if (ehdr->e_shoff >= offset)
		ehdr->e_shoff += bytes;
	if (ehdr->e_phoff >= offset)
		ehdr->e_phoff += bytes;

	Elf32_Phdr *phdr = (Elf32_Phdr*)iehdr->phdrs;
	int start, end;
	int i;
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_GNU_STACK)
			continue;

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_offset <= offset) {
				//merge dumb section into this segment
				phdr->p_vaddr -= bytes;
				phdr->p_paddr -= bytes;
				phdr->p_filesz += bytes;
				phdr->p_memsz += bytes;
			}
			else 
				phdr->p_offset += bytes;
		}
		else {
			if (phdr->p_vaddr == 0) {
				if (phdr->p_offset != 0)
					phdr->p_offset += bytes;
				continue;
			}

			start = phdr->p_offset;
			end = start + phdr->p_filesz;
			if ((start < offset) && (end <= offset)) {
				phdr->p_vaddr -= bytes;
				phdr->p_paddr -= bytes;
			}
			else if (start >= offset) {
				phdr->p_offset += bytes;
			}
			else {
				perror("Unexpected Section Alignment!");
				return false;
			}
		}
	}

	Elf32_Shdr *shdr = (Elf32_Shdr*)iehdr->shdrs;
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_NULL)
			continue;

		start = shdr->sh_offset;
		end = start + shdr->sh_size;
		if ((start < offset) && (end <= offset)) {
			shdr->sh_addr -= bytes;
		}
		else if(start == offset) {
			shdr->sh_offset += bytes;
		}
		else if (start > offset) {
			shdr->sh_offset += bytes;
		}
		else {
			perror("Unexpected Section Alignment!");
			return false;
		}
	}
	return true;
}


	EXPORT bool
insert_dumb_section(elf_t *obj, Elf_Internal_Shdr *dumb)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	int oft = dumb->sh_offset;
	int bytes = (dumb->sh_size + PAGE_SIZE -1) & (-PAGE_SIZE);

	//Adjust internal structures
	Elf_Internal_Phdr *phdr = obj->program_headers;
	int start, end;
	int i;
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_GNU_STACK)
			continue;

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_offset < oft) {
				phdr->p_vaddr -= bytes;
				phdr->p_paddr -= bytes;
				phdr->p_filesz += bytes;
				phdr->p_memsz += bytes;
			}
			else {
				phdr->p_offset += bytes;
			}
		}
		else {
			if (phdr->p_vaddr == 0)
				continue;

			start = phdr->p_offset;
			end = start + phdr->p_filesz;
			if ((start < oft) && (end <= oft)) {
				phdr->p_vaddr -= bytes;
				phdr->p_paddr -= bytes;
			}
			else if (start >= oft) {
				phdr->p_offset += bytes;
			}
			else {
				fprintf(stderr, "Unexpected Section Alignment!");
				return false;
			}
		}
	}

	Elf_Internal_Shdr *shdr = obj->section_headers;

	obj->section_headers = (Elf_Internal_Shdr*)xrealloc(
			shdr, (ehdr->e_shnum+1) * sizeof(Elf_Internal_Shdr));
	shdr = obj->section_headers;

	i = 0;
	while (shdr->sh_offset != oft) {i++, shdr++;}
	Elf_Internal_Shdr *tmphdr = shdr;
	tmphdr ++;

	memmove(tmphdr, shdr, (ehdr->e_shnum - i)*sizeof(Elf_Internal_Shdr));
	memcpy(shdr, dumb, sizeof(Elf_Internal_Shdr));
	ehdr->e_shnum++;

	shdr = obj->section_headers;
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_NULL)
			continue;
		if (shdr->sh_type == SHT_DUMB)
			continue;

		start = shdr->sh_offset;
		end = start + shdr->sh_size;
		if ((start < oft) && (end <= oft)) {
			if (shdr->sh_addr != 0)
				shdr->sh_addr -= bytes;
		}
		else if ((start == oft) && (shdr->sh_type != SHT_DUMB)) {
			shdr->sh_offset += bytes;
		}
		else if (start > oft) {
			shdr->sh_offset += bytes;
		}
		else {
			fprintf(stderr, "Unexpected Section Alignment!");
			return false;
		}
	}

	if (ehdr->e_shoff >= oft) {
		ehdr->e_shoff += bytes;
	}
	//modify data blocks of binary content
	if (obj->is_32bit) 
		adjust_elf32_binary_for_dumb_section(obj, oft, bytes);

	return true;	
}

typedef struct {
	long offset;
	char *pdata;
	long nbytes;
} Elf_Data;

int data_blk_offset_comp(const void *p1, const void *p2)
{
	Elf_Data *e1 = (Elf_Data*)p1;
	Elf_Data *e2 = (Elf_Data*)p2;

	return ((e1->offset > e2->offset) - 
			(e1->offset < e2->offset));
}

void output_elf_object(elf_t *obj, const char* elf_file)
{
	int fd;

	fd = open(elf_file, O_RDWR|O_CREAT|O_TRUNC, 0775);
	if (fd < 0) {
		perror("Open output file failed.");
		exit(EXIT_FAILURE);
	}

	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *shdrs = obj->section_headers;
	Elf_Data *ar = NULL;
	int nparts, i, j;

	nparts = 3 + ehdr->e_shnum;
	ar = (Elf_Data*)xcalloc(nparts, sizeof(Elf_Data));
	ar[0].pdata = ehdr->ehdr;
	ar[0].offset = 0;
	ar[0].nbytes = ehdr->e_ehsize;
	ar[1].pdata = ehdr->phdrs;
	ar[1].offset = ehdr->e_phoff;
	ar[1].nbytes = ehdr->e_phnum * ehdr->e_phentsize;
	ar[2].pdata = ehdr->shdrs;
	ar[2].offset = ehdr->e_shoff;
	ar[2].nbytes = ehdr->e_shnum * ehdr->e_shentsize;

	for (j=0, i=3; j < ehdr->e_shnum; j++, i++) {
		ar[i].pdata = shdrs[j].binary;
		ar[i].offset = shdrs[j].sh_offset;
		ar[i].nbytes = shdrs[j].sh_size;
	}	   
	qsort(ar, nparts, sizeof(Elf_Data), data_blk_offset_comp);

	int alloc = 256;
	char* zeros = (char*)xmalloc(alloc);
	memset(zeros, 0, alloc);
	int len, pos = 0;
	for (i = 0; i < nparts; i++) {
		//printf("%lx\t%lx\n", ar[i].offset, ar[i].offset + ar[i].nbytes);
		//pading
		if (pos < ar[i].offset) {
			len = ar[i].offset - pos;
			while (len > alloc) {
				alloc *= 2;
				zeros = (char*) xmalloc(alloc);
				memset(zeros, 0, alloc);
			}
			pwrite(fd, zeros, len, pos);
			pos = pos + len;
		}

		if (ar[i].nbytes != 0) {
			pwrite(fd, ar[i].pdata, ar[i].nbytes, ar[i].offset);
			pos = ar[i].offset + ar[i].nbytes;
		}
	}
	free(zeros);
	free(ar);
	close(fd);
}

	bool 
patch_section_data(elf_t *obj, cfi_vma addr, const char *patch, int len)
{
	Elf_Internal_Ehdr *ehdr = &obj->elf_header;
	Elf_Internal_Shdr *shdr = obj->section_headers;
	cfi_vma start, end;
	bool bfind;
	int i;

	bfind = false;
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_DUMB)
			continue;

		start = shdr->sh_addr;
		end = start + shdr->sh_size;
		if ((start <= addr) && (addr < end)) {
			bfind = true;
			break;
		}
	}
	if (!bfind)
		return false;
	cfi_vma oft = addr - start;
	memcpy(shdr->binary+oft, patch, len);

	return true;
}


