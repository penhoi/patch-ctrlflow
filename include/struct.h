#ifndef __STRUCT_H__
#define __STRUCT_H__

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#define EXPORT
#ifndef __cplusplus
typedef int bool;
#define false 0
#define true 1
#endif

#ifdef __cplusplus
extern "C" {
#endif //#__cplusplus

	typedef unsigned long cfi_vma;
	typedef int (*sprintf_ft) (void *_this, const char*, ...);
	typedef bool (*checker_ft) (const void *rule, const void *obj);
	typedef void* (*find_ft) (void *_this, const void* key);
	typedef bool (*add_ft)(void* _this, const void *);

	enum CODEBLK_TYPE{
		CT_NORMAL = 0,
		CT_NEEDPATCH = 1,
		CT_BEPATCH = 2,
	};
	/* object for storing a block of asmcode.*/
	typedef struct asmcode_blk_t {
		size_t alloc, pos;
		char *buffer;
		enum CODEBLK_TYPE type;
		cfi_vma startvma, endvma;
		sprintf_ft sprintf;
	} asmcode_blk_t;

	/* keeps all asmcode of an elf file*/
	typedef struct elf_cfi_t elf_cfi_t;
	typedef struct elf_asmcode_t {
		char* file;
		size_t alloc, pos;
		asmcode_blk_t **ar;
		add_ft add_block;
		sprintf_ft sprintf;    
		elf_cfi_t *cfi;
	}elf_asmcode_t;

	/* information of control flow transfers */
	typedef struct {
		cfi_vma tovma;
		size_t freq;
	}toinfo_t;

	typedef struct cfi_info_t {
		size_t alloc, pos;
		cfi_vma fromvma;
		toinfo_t *info;
	}cfi_info_t;

	typedef struct elf_cfi_t {
		size_t alloc;
		size_t pos;
		cfi_info_t **ar;
		add_ft add_node;
		find_ft find_node;
	}elf_cfi_t;

	elf_asmcode_t* disasm_elf_file (char *elf_file, checker_ft, elf_cfi_t*);

	asmcode_blk_t* explicitate_cfi (cfi_info_t*, asmcode_blk_t**);

	/* ELF Header */
	typedef struct elf_internal_ehdr {
		unsigned char     e_ident[EI_NIDENT]; /* ELF "magic number" */
		long       e_entry;    /* Entry point virtual address */
		unsigned long     e_phoff;    /* Program header table file offset */
		unsigned long     e_shoff;    /* Section header table file offset */
		unsigned long     e_version;  /* Identifies object file version */
		unsigned long     e_flags;    /* Processor-specific flags */
		unsigned short    e_type;     /* Identifies object file type */
		unsigned short    e_machine;  /* Specifies required architecture */
		unsigned int      e_ehsize;   /* ELF header size in bytes */
		unsigned int      e_phentsize;    /* Program header table entry size */
		unsigned int      e_phnum;    /* Program header table entry count */
		unsigned int      e_shentsize;    /* Section header table entry size */
		unsigned int      e_shnum;    /* Section header table entry count */
		unsigned int      e_shstrndx; /* Section header string table index */
		cfi_vma base_address;
		char *ehdr;
		char *shdrs;
		char *phdrs;
	} Elf_Internal_Ehdr;

	/* Program header */

	typedef struct elf_internal_phdr {
		unsigned long p_type;         /* Identifies program segment type */
		unsigned long p_flags;        /* Segment flags */
		long   p_offset;       /* Segment file offset */
		long   p_vaddr;        /* Segment virtual address */
		long   p_paddr;        /* Segment physical address */
		long   p_filesz;       /* Segment size in file */
		long   p_memsz;        /* Segment size in memory */
		long   p_align;        /* Segment alignment, file & memory */
		char* binary;	
	} Elf_Internal_Phdr;

	/* Section header */
	typedef struct elf_internal_shdr {
		unsigned int  sh_name;        /* Section name, index in string tbl */
		unsigned int  sh_type;        /* Type of section */
		long   sh_flags;       /* Miscellaneous section attributes */
		long   sh_addr;        /* Section virtual addr at execution */
		long  sh_offset;      /* Section file offset */
		unsigned long sh_size;        /* Size of section in bytes */
		unsigned int  sh_link;        /* Index of another section */
		unsigned int  sh_info;        /* Additional section information */
		long   sh_addralign;       /* Section alignment */
		unsigned long sh_entsize;     /* Entry size if section holds table */

		/* The internal rep also has some cached info associated with it. */
		char *binary;      /* Section contents.  */
	} Elf_Internal_Shdr;


	typedef struct elf_t {
		char *file;
		bool is_32bit;
		cfi_vma dynamic_info[DT_ENCODING];
		Elf_Internal_Ehdr elf_header;
		Elf_Internal_Shdr * section_headers;
		Elf_Internal_Phdr * program_headers;
	}elf_t;
#define PAGE_SIZE 0x1000

	elf_t* parse_elf_file (char * elf_file);
	bool adjust_base_address(elf_t *obj, long new_ba);
	Elf_Internal_Shdr * prelayout_dumb_section (const elf_t *obj);
	bool insert_dumb_section(elf_t *obj, Elf_Internal_Shdr *dumb);
	void output_elf_object(elf_t *obj, const char* elf_name);
	bool patch_section_data(elf_t *obj, cfi_vma vma, const char *patch, int len);

#ifdef __cplusplus
}
#endif //#__cplusplus

#endif //#ifndef __STRUCT_H__

