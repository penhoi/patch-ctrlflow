#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <bfd.h>
#include <dis-asm.h>
#include "struct.h"

/* sprintf to a "stream".  */
	int ATTRIBUTE_PRINTF_2
objdump_sprintf (asmcode_blk_t *f, const char *format, ...)
{
	size_t n;
	va_list args;

	while (1) {
		size_t space = f->alloc - f->pos;

		va_start (args, format);
		n = vsnprintf (f->buffer + f->pos, space, format, args);
		va_end (args);

		if (space > n)
			break;

		f->alloc = (f->alloc + n) * 2;
		f->buffer = (char *) xrealloc (f->buffer, f->alloc);
	}
	f->pos += n;

	return n;
}


/* default print function for output assembly results. */
	static void
elf_asmcode_printf(elf_asmcode_t *code, const char* dumb, ...)
{
	asmcode_blk_t **ar = code->ar;
	int i;

	for (i = 0; i< code->pos; i++) {
		printf("\t.org 0x%lx\n", (long)(ar[i]->startvma));
		printf("%s\n", ar[i]->buffer);
	}
}

	static bool
elf_asmcode_add_block(elf_asmcode_t *code, asmcode_blk_t *blk)
{
	asmcode_blk_t **ar = code->ar;

	ar[code->pos++] = blk;
	if (code->pos >= code->alloc) {
		code->alloc *= 2;
		code->ar = (asmcode_blk_t**) 
			xrealloc(ar, code->alloc * sizeof(asmcode_blk_t*));
	}
}


#define _(str) gettext(str)

/* The following variables are set based on arguments passed on the
   command line.  */
static int dump_reloc_info;		/* -r */
static int dump_dynamic_reloc_info;	/* -R */
static int prefix_addresses;		/* --prefix-addresses */
static int show_raw_insn;		/* --show-raw-insn */
static bfd_boolean disassemble;		/* -d */
static bfd_boolean disassemble_all;	/* -D */
static int disassemble_zeroes;		/* --disassemble-zeroes */
static int wide_output;			/* -w */
static int insn_width;			/* --insn-width */
static bfd_vma start_address = (bfd_vma) -1; /* --start-address */
static bfd_vma stop_address = (bfd_vma) -1;  /* --stop-address */


/* Extra info to pass to the section disassembler and address printing
   function.  */
struct objdump_disasm_info
{
	bfd *              abfd;
	asection *         sec;
	bfd_boolean        require_sec;
	arelent **         dynrelbuf;
	long               dynrelcount;
	disassembler_ftype disassemble_fn;
	elf_asmcode_t *    code;
	checker_ft         patch_blk_p;
	arelent *          reloc;
};

/* Architecture to disassemble for, or default if NULL.  */
static char *machine = NULL;

/* Target specific options to the disassembler.  */
static char *disassembler_options = NULL;

/* Endianness to disassemble for, or default if BFD_ENDIAN_UNKNOWN.  */
static enum bfd_endian endian = BFD_ENDIAN_UNKNOWN;

/* The symbol table.  */
static asymbol **syms;

/* Number of symbols in `syms'.  */
static long symcount = 0;

/* The sorted symbol table.  */
static asymbol **sorted_syms;

/* Number of symbols in `sorted_syms'.  */
static long sorted_symcount = 0;

/* The dynamic symbol table.  */
static asymbol **dynsyms;

/* The synthetic symbol table.  */
static asymbol *synthsyms;
static long synthcount = 0;

/* Number of symbols in `dynsyms'.  */
static long dynsymcount = 0;

	void
bfd_nonfatal (const char *string)
{
	const char *errmsg;

	errmsg = bfd_errmsg (bfd_get_error ());
	fflush (stdout);
	if (string)
		fprintf (stderr, "%s: %s\n", string, errmsg);
	else
		fprintf (stderr, "%s\n", errmsg);
}

	void
bfd_fatal (const char *string)
{
	bfd_nonfatal (string);
	exit (1);
}

	static asymbol **
slurp_symtab (bfd *abfd)
{
	asymbol **sy = NULL;
	long storage;

	if (!(bfd_get_file_flags (abfd) & HAS_SYMS)) {
		symcount = 0;
		return NULL;
	}

	storage = bfd_get_symtab_upper_bound (abfd);
	if (storage < 0)
		bfd_fatal (bfd_get_filename (abfd));
	if (storage)
		sy = (asymbol **) xmalloc (storage);

	symcount = bfd_canonicalize_symtab (abfd, sy);
	if (symcount < 0)
		bfd_fatal (bfd_get_filename (abfd));
	return sy;
}

/* Read in the dynamic symbols.  */

	static asymbol **
slurp_dynamic_symtab (bfd *abfd)
{
	asymbol **sy = NULL;
	long storage;

	storage = bfd_get_dynamic_symtab_upper_bound (abfd);
	if (storage < 0) {
		if (!(bfd_get_file_flags (abfd) & DYNAMIC)) {
			bfd_nonfatal (_("not a dynamic object"));
			dynsymcount = 0;
			return NULL;
		}

		bfd_fatal (bfd_get_filename (abfd));
	}
	if (storage)
		sy = (asymbol **) xmalloc (storage);

	dynsymcount = bfd_canonicalize_dynamic_symtab (abfd, sy);
	if (dynsymcount < 0)
		bfd_fatal (bfd_get_filename (abfd));
	return sy;
}

/* Filter out (in place) symbols that are useless for disassembly.
   COUNT is the number of elements in SYMBOLS.
   Return the number of useful symbols.  */

	static long
remove_useless_symbols (asymbol **symbols, long count)
{
	asymbol **in_ptr = symbols, **out_ptr = symbols;

	while (--count >= 0) {
		asymbol *sym = *in_ptr++;

		if (sym->name == NULL || sym->name[0] == '\0')
			continue;
		if (sym->flags & (BSF_DEBUGGING | BSF_SECTION_SYM))
			continue;
		if (bfd_is_und_section (sym->section)
				|| bfd_is_com_section (sym->section))
			continue;

		*out_ptr++ = sym;
	}
	return out_ptr - symbols;
}

/* Sort symbols into value order.  */

	static int
compare_symbols (const void *ap, const void *bp)
{
	const asymbol *a = * (const asymbol **) ap;
	const asymbol *b = * (const asymbol **) bp;
	const char *an;
	const char *bn;
	size_t anl;
	size_t bnl;
	bfd_boolean af;
	bfd_boolean bf;
	flagword aflags;
	flagword bflags;

	if (bfd_asymbol_value (a) > bfd_asymbol_value (b))
		return 1;
	else if (bfd_asymbol_value (a) < bfd_asymbol_value (b))
		return -1;

	if (a->section > b->section)
		return 1;
	else if (a->section < b->section)
		return -1;

	an = bfd_asymbol_name (a);
	bn = bfd_asymbol_name (b);
	anl = strlen (an);
	bnl = strlen (bn);

	/* The symbols gnu_compiled and gcc2_compiled convey no real
	   information, so put them after other symbols with the same value.  */
	af = (strstr (an, "gnu_compiled") != NULL
			|| strstr (an, "gcc2_compiled") != NULL);
	bf = (strstr (bn, "gnu_compiled") != NULL
			|| strstr (bn, "gcc2_compiled") != NULL);

	if (af && ! bf)
		return 1;
	if (! af && bf)
		return -1;

	/* We use a heuristic for the file name, to try to sort it after
	   more useful symbols.  It may not work on non Unix systems, but it
	   doesn't really matter; the only difference is precisely which
	   symbol names get printed.  */

#define file_symbol(s, sn, snl)			\
	(((s)->flags & BSF_FILE) != 0			\
	 || ((sn)[(snl) - 2] == '.'			\
		 && ((sn)[(snl) - 1] == 'o'		\
			 || (sn)[(snl) - 1] == 'a')))

	af = file_symbol (a, an, anl);
	bf = file_symbol (b, bn, bnl);

	if (af && ! bf)
		return 1;
	if (! af && bf)
		return -1;

	/* Try to sort global symbols before local symbols before function
	   symbols before debugging symbols.  */

	aflags = a->flags;
	bflags = b->flags;

	if ((aflags & BSF_DEBUGGING) != (bflags & BSF_DEBUGGING))
	{
		if ((aflags & BSF_DEBUGGING) != 0)
			return 1;
		else
			return -1;
	}
	if ((aflags & BSF_FUNCTION) != (bflags & BSF_FUNCTION))
	{
		if ((aflags & BSF_FUNCTION) != 0)
			return -1;
		else
			return 1;
	}
	if ((aflags & BSF_LOCAL) != (bflags & BSF_LOCAL))
	{
		if ((aflags & BSF_LOCAL) != 0)
			return 1;
		else
			return -1;
	}
	if ((aflags & BSF_GLOBAL) != (bflags & BSF_GLOBAL))
	{
		if ((aflags & BSF_GLOBAL) != 0)
			return -1;
		else
			return 1;
	}

	/* Symbols that start with '.' might be section names, so sort them
	   after symbols that don't start with '.'.  */
	if (an[0] == '.' && bn[0] != '.')
		return 1;
	if (an[0] != '.' && bn[0] == '.')
		return -1;

	/* Finally, if we can't distinguish them in any other way, try to
	   get consistent results by sorting the symbols by name.  */
	return strcmp (an, bn);
}

/* Sort relocs into address order.  */

	static int
compare_relocs (const void *ap, const void *bp)
{
	const arelent *a = * (const arelent **) ap;
	const arelent *b = * (const arelent **) bp;

	if (a->address > b->address)
		return 1;
	else if (a->address < b->address)
		return -1;

	/* So that associated relocations tied to the same address show up
	   in the correct order, we don't do any further sorting.  */
	if (a > b)
		return 1;
	else if (a < b)
		return -1;
	else
		return 0;
}

/* Print an address (VMA) to the output stream in INFO.
   If SKIP_ZEROES is TRUE, omit leading zeroes.  */

	static void
objdump_print_value (bfd_vma vma, struct disassemble_info *inf,
		bfd_boolean skip_zeroes)
{
	char buf[30];
	char *p;
	struct objdump_disasm_info *aux;

	aux = (struct objdump_disasm_info *) inf->application_data;
	bfd_sprintf_vma (aux->abfd, buf, vma);
	if (! skip_zeroes)
		p = buf;
	else
	{
		for (p = buf; *p == '0'; ++p);
		if (*p == '\0')
			--p;
	}
	(*inf->fprintf_func) (inf->stream, "%s", p);
}

/* Print the name of a symbol.  */

	static void
objdump_print_symname (bfd *abfd, struct disassemble_info *inf,
		asymbol *sym)
{
	char *alloc;
	const char *name;

	alloc = NULL;
	name = bfd_asymbol_name (sym);

	if (inf != NULL)
		(*inf->fprintf_func) (inf->stream, "%s", name);
	else
		printf ("%s", name);

	if (alloc != NULL)
		free (alloc);
}

/* Locate a symbol given a bfd and a section (from INFO->application_data),
   and a VMA.  If INFO->application_data->require_sec is TRUE, then always
   require the symbol to be in the section.  Returns NULL if there is no
   suitable symbol.  If PLACE is not NULL, then *PLACE is set to the index
   of the symbol in sorted_syms.  */

	static asymbol *
find_symbol_for_address (bfd_vma vma,
		struct disassemble_info *inf,
		long *place)
{
	/* @@ Would it speed things up to cache the last two symbols returned,
	   and maybe their address ranges?  For many processors, only one memory
	   operand can be present at a time, so the 2-entry cache wouldn't be
	   constantly churned by code doing heavy memory accesses.  */

	/* Indices in `sorted_syms'.  */
	long min = 0;
	long max_count = sorted_symcount;
	long thisplace;
	struct objdump_disasm_info *aux;
	bfd *abfd;
	asection *sec;
	unsigned int opb;
	bfd_boolean want_section;

	if (sorted_symcount < 1)
		return NULL;

	aux = (struct objdump_disasm_info *) inf->application_data;
	abfd = aux->abfd;
	sec = aux->sec;
	opb = inf->octets_per_byte;

	/* Perform a binary search looking for the closest symbol to the
	   required value.  We are searching the range (min, max_count].  */
	while (min + 1 < max_count)
	{
		asymbol *sym;

		thisplace = (max_count + min) / 2;
		sym = sorted_syms[thisplace];

		if (bfd_asymbol_value (sym) > vma)
			max_count = thisplace;
		else if (bfd_asymbol_value (sym) < vma)
			min = thisplace;
		else
		{
			min = thisplace;
			break;
		}
	}

	/* The symbol we want is now in min, the low end of the range we
	   were searching.  If there are several symbols with the same
	   value, we want the first one.  */
	thisplace = min;
	while (thisplace > 0
			&& (bfd_asymbol_value (sorted_syms[thisplace])
				== bfd_asymbol_value (sorted_syms[thisplace - 1])))
		--thisplace;

	/* Prefer a symbol in the current section if we have multple symbols
	   with the same value, as can occur with overlays or zero size
	   sections.  */
	min = thisplace;
	while (min < max_count
			&& (bfd_asymbol_value (sorted_syms[min])
				== bfd_asymbol_value (sorted_syms[thisplace])))
	{
		if (sorted_syms[min]->section == sec
				&& inf->symbol_is_valid (sorted_syms[min], inf))
		{
			thisplace = min;

			if (place != NULL)
				*place = thisplace;

			return sorted_syms[thisplace];
		}
		++min;
	}

	/* If the file is relocatable, and the symbol could be from this
	   section, prefer a symbol from this section over symbols from
	   others, even if the other symbol's value might be closer.

	   Note that this may be wrong for some symbol references if the
	   sections have overlapping memory ranges, but in that case there's
	   no way to tell what's desired without looking at the relocation
	   table.

	   Also give the target a chance to reject symbols.  */
	want_section = (aux->require_sec
			|| ((abfd->flags & HAS_RELOC) != 0
				&& vma >= bfd_get_section_vma (abfd, sec)
				&& vma < (bfd_get_section_vma (abfd, sec)
					+ bfd_section_size (abfd, sec) / opb)));
	if ((sorted_syms[thisplace]->section != sec && want_section)
			|| ! inf->symbol_is_valid (sorted_syms[thisplace], inf))
	{
		long i;
		long newplace = sorted_symcount;

		for (i = min - 1; i >= 0; i--)
		{
			if ((sorted_syms[i]->section == sec || !want_section)
					&& inf->symbol_is_valid (sorted_syms[i], inf))
			{
				if (newplace == sorted_symcount)
					newplace = i;

				if (bfd_asymbol_value (sorted_syms[i])
						!= bfd_asymbol_value (sorted_syms[newplace]))
					break;

				/* Remember this symbol and keep searching until we reach
				   an earlier address.  */
				newplace = i;
			}
		}

		if (newplace != sorted_symcount)
			thisplace = newplace;
		else
		{
			/* We didn't find a good symbol with a smaller value.
			   Look for one with a larger value.  */
			for (i = thisplace + 1; i < sorted_symcount; i++)
			{
				if ((sorted_syms[i]->section == sec || !want_section)
						&& inf->symbol_is_valid (sorted_syms[i], inf))
				{
					thisplace = i;
					break;
				}
			}
		}

		if ((sorted_syms[thisplace]->section != sec && want_section)
				|| ! inf->symbol_is_valid (sorted_syms[thisplace], inf))
			/* There is no suitable symbol.  */
			return NULL;
	}

	if (place != NULL)
		*place = thisplace;

	return sorted_syms[thisplace];
}

/* Print an address and the offset to the nearest symbol.  */

	static void
objdump_print_addr_with_sym (bfd *abfd, asection *sec, asymbol *sym,
		bfd_vma vma, struct disassemble_info *inf,
		bfd_boolean skip_zeroes)
{
	objdump_print_value (vma, inf, skip_zeroes);

	if (sym == NULL)
	{
		bfd_vma secaddr;

		(*inf->fprintf_func) (inf->stream, " <%s",
				bfd_get_section_name (abfd, sec));
		secaddr = bfd_get_section_vma (abfd, sec);
		if (vma < secaddr)
		{
			(*inf->fprintf_func) (inf->stream, "-0x");
			objdump_print_value (secaddr - vma, inf, TRUE);
		}
		else if (vma > secaddr)
		{
			(*inf->fprintf_func) (inf->stream, "+0x");
			objdump_print_value (vma - secaddr, inf, TRUE);
		}
		(*inf->fprintf_func) (inf->stream, ">");
	}
	else
	{	
		(*inf->fprintf_func) (inf->stream, " <");
		objdump_print_symname (abfd, inf, sym);
		if (bfd_asymbol_value (sym) > vma)
		{
			(*inf->fprintf_func) (inf->stream, "-0x");
			objdump_print_value (bfd_asymbol_value (sym) - vma, inf, TRUE);
		}
		else if (vma > bfd_asymbol_value (sym))
		{
			(*inf->fprintf_func) (inf->stream, "+0x");
			objdump_print_value (vma - bfd_asymbol_value (sym), inf, TRUE);
		}
		(*inf->fprintf_func) (inf->stream, ">");
	}

}

/* Print an address (VMA), symbolically if possible.
   If SKIP_ZEROES is TRUE, don't output leading zeroes.  */

	static void
objdump_print_addr (bfd_vma vma,
		struct disassemble_info *inf,
		bfd_boolean skip_zeroes)
{
	struct objdump_disasm_info *aux;
	asymbol *sym = NULL;
	bfd_boolean skip_find = FALSE;

	aux = (struct objdump_disasm_info *) inf->application_data;

	if (sorted_symcount < 1)
	{
		(*inf->fprintf_func) (inf->stream, "0x");
		objdump_print_value (vma, inf, skip_zeroes);
		return;
	}

	if (aux->reloc != NULL
			&& aux->reloc->sym_ptr_ptr != NULL
			&& * aux->reloc->sym_ptr_ptr != NULL)
	{
		sym = * aux->reloc->sym_ptr_ptr;

		/* Adjust the vma to the reloc.  */
		vma += bfd_asymbol_value (sym);

		if (bfd_is_und_section (bfd_get_section (sym)))
			skip_find = TRUE;
	}

	if (!skip_find)
		sym = find_symbol_for_address (vma, inf, NULL);

	//objdump_print_addr_with_sym (aux->abfd, aux->sec, sym, vma, inf,
	//		skip_zeroes);
	(*inf->fprintf_func) (inf->stream, "glab_");
	objdump_print_value (vma, inf, FALSE);
}

/* Print VMA to INFO.  This function is passed to the disassembler
   routine.  */

	static void
objdump_print_address (bfd_vma vma, struct disassemble_info *inf)
{
	objdump_print_addr (vma, inf, ! prefix_addresses);
}

/* Determine if the given address has a symbol associated with it.  */

	static int
objdump_symbol_at_address (bfd_vma vma, struct disassemble_info * inf)
{
	asymbol * sym;

	sym = find_symbol_for_address (vma, inf, NULL);

	return (sym != NULL && (bfd_asymbol_value (sym) == vma));
}



/* The number of zeroes we want to see before we start skipping them.
   The number is arbitrarily chosen.  */

#define DEFAULT_SKIP_ZEROES 8

/* The number of zeroes to skip at the end of a section.  If the
   number of zeroes at the end is between SKIP_ZEROES_AT_END and
   SKIP_ZEROES, they will be disassembled.  If there are fewer than
   SKIP_ZEROES_AT_END, they will be skipped.  This is a heuristic
   attempt to avoid disassembling zeroes inserted by section
   alignment.  */

//#define DEFAULT_SKIP_ZEROES_AT_END 3
#define DEFAULT_SKIP_ZEROES_AT_END 0

	bool 
sprintf_asmcode(const bfd_byte *data, int octets, bfd_vma vma,
		const asmcode_blk_t *asmcode, 
		asmcode_blk_t *blk, bool *dumb)
{
	//current asm instruction is used for padding; 
	//then we start "dumb" mode that does not print next padding insts any more.
	bfd_boolean bPadIns = FALSE, bJmpIns = FALSE;
	long addr;

	//Before output the disassemble results, we firstly correct 
	//labels on some cornercases, in order to pass though the gcc compiling. 
	if ((data[0] == 0x74) && (data[1] == 0x01)) {					
#define JE1 "je     glab_"
#define JE1LEN  (sizeof(JE1)-1)
		addr = strtol(&asmcode->buffer[JE1LEN], NULL, 16) - 1; 
		(blk->sprintf) (blk, "\tje     glab_%08lx+1", addr);
	}
#define LEAPADDI "lea    0x0(%edi,%eiz,1),%edi"
#define LEAPADSI "lea    0x0(%esi,%eiz,1),%esi"
#define LEAPADLEN (sizeof(LEAPADDI)-1)
	else if ((asmcode->pos == LEAPADLEN) && 
			(!strcasecmp(asmcode->buffer, LEAPADDI) || 
			 !strcasecmp(asmcode->buffer, LEAPADSI))) {
		bPadIns = TRUE;
	}
#define XCHG0 "xchg   %ax,%ax"
#define XCHG0LEN (sizeof(XCHG0)-1)
	else if ((asmcode->pos == XCHG0LEN) && 
			!strcasecmp(asmcode->buffer, XCHG0)) {
		bPadIns = TRUE;
		if (!dumb)
			(blk->sprintf) (blk, "\t%s", asmcode->buffer);
	}
#define NOP "nop"
#define NOPLEN (sizeof(NOP)-1)
	else if ((asmcode->pos == NOPLEN) && 
			!strcasecmp(asmcode->buffer, NOP)) {
		bPadIns = TRUE;
		if (!dumb)
			(blk->sprintf) (blk, "\t%s", asmcode->buffer);
	}
#define JMPINS "jmp    glab_"
#define JMPINSLEN (sizeof(JMPINS)-1)
	else if (!strncasecmp(asmcode->buffer, JMPINS, JMPINSLEN)) {
		bool bnear = false;
		bJmpIns = TRUE;

		if ((octets == 2) && (blk->type == CT_NORMAL)) {
			long oft;

			addr = strtol(&asmcode->buffer[JMPINSLEN], NULL, 16);
			oft = vma - addr;
			if (oft >= 0)
				(blk->sprintf) (blk, "\tjmp   .-0x%02x", (char)oft);
			else
				(blk->sprintf) (blk, "\tjmp   .+0x%02x", (char)-oft);
		}
		else
			(blk->sprintf) (blk, "\t%s", asmcode->buffer);
	}
	//default
	else
		(blk->sprintf) (blk, "\t%s", asmcode->buffer);				

	*dumb = bPadIns || bJmpIns;
	return true;
}
/* Disassemble some data in memory between given values.  */

	static void
disassemble_bytes (struct disassemble_info * inf,
		disassembler_ftype        disassemble_fn,
		bfd_boolean               insns,
		bfd_byte *                data,
		bfd_vma                   start_offset,
		bfd_vma                   stop_offset,
		bfd_vma		     rel_offset,
		arelent ***               relppp,
		arelent **                relppend)
{
	struct objdump_disasm_info *aux;
	asection *section;
	int octets_per_line;
	bfd_vma addr_offset;
	unsigned int opb = inf->octets_per_byte;
	unsigned int skip_zeroes = inf->skip_zeroes;
	unsigned int skip_zeroes_at_end = inf->skip_zeroes_at_end;
	int octets = opb;
	bfd_boolean bdumb;

	aux = (struct objdump_disasm_info *) inf->application_data;
	section = aux->sec;

	asmcode_blk_t *codeblk = (asmcode_blk_t*) xmalloc(sizeof(asmcode_blk_t));
	codeblk->startvma = section->vma + start_offset;
	codeblk->endvma = section->vma + stop_offset;
	codeblk->alloc = (stop_offset-start_offset) * 15;
	codeblk->buffer = (char *) xmalloc (codeblk->alloc);
	codeblk->pos = 0;
	codeblk->sprintf= (sprintf_ft)objdump_sprintf;
	codeblk->type = 
		(aux->patch_blk_p)(aux->code->cfi, codeblk)?CT_NEEDPATCH:CT_NORMAL;

	asmcode_blk_t asmcode;
	asmcode.alloc = 120;
	asmcode.buffer = (char *) xmalloc (asmcode.alloc);
	asmcode.pos = 0;
	asmcode.sprintf= (sprintf_ft)objdump_sprintf;
	inf->fprintf_func = (fprintf_ftype) objdump_sprintf;
	inf->stream = &asmcode;

	if (insn_width)
		octets_per_line = insn_width;
	else if (insns)
		octets_per_line = 4;
	else
		octets_per_line = 16;

	inf->insn_info_valid = 0;

	addr_offset = start_offset;
	while (addr_offset < stop_offset)
	{
		bfd_vma z;
		bfd_boolean need_nl = FALSE;
		int previous_octets;

		/* Remember the length of the previous instruction.  */
		previous_octets = octets;
		octets = 0;

		/* Make sure we don't use relocs from previous instructions.  */
		aux->reloc = NULL;

		/* If we see more than SKIP_ZEROES octets of zeroes, we just
		   print `...'.  */
		for (z = addr_offset * opb; z < stop_offset * opb; z++)
			if (data[z] != 0)
				break;
		if (! disassemble_zeroes
				&& (inf->insn_info_valid == 0
					|| inf->branch_delay_insns == 0)
				&& (z - addr_offset * opb >= skip_zeroes
					|| (z == stop_offset * opb &&
						z - addr_offset * opb < skip_zeroes_at_end)))
		{
			/* If there are more nonzero octets to follow, we only skip
			   zeroes in multiples of 4, to try to avoid running over
			   the start of an instruction which happens to start with
			   zero.  */
			if (z != stop_offset * opb)
				z = addr_offset * opb + ((z - addr_offset * opb) &~ 3);

			octets = z - addr_offset * opb;

			/* If we are going to display more data, and we are displaying
			   file offsets, then tell the user how many zeroes we skip
			   and the file offset from where we resume dumping.  */
			if ((addr_offset + (octets / opb)) < stop_offset)
				printf ("\t... (skipping %d zeroes, resuming at file offset: 0x%lx)\n",
						octets / opb,
						(unsigned long) (section->filepos
							+ (addr_offset + (octets / opb))));
			else
				printf ("\t...\n");
		}
		else
		{
			char buf[50];
			int bpc = 0;
			int pb = 0;

			if (! prefix_addresses)
			{
				char *s;

				bfd_sprintf_vma (aux->abfd, buf, section->vma + addr_offset);
				(codeblk->sprintf) (codeblk, "glab_%s:\n", buf);
			}
			else
			{
				aux->require_sec = TRUE;
				objdump_print_address (section->vma + addr_offset, inf);
				aux->require_sec = FALSE;
				objdump_sprintf(codeblk, " ");
			}

			if (insns)
			{
				asmcode.pos = 0;
				inf->bytes_per_line = 0;
				inf->bytes_per_chunk = 0;
				inf->flags = disassemble_all ? DISASSEMBLE_DATA : 0;
				if (machine)
					inf->flags |= USER_SPECIFIED_MACHINE_TYPE;

				if (inf->disassembler_needs_relocs
						&& (bfd_get_file_flags (aux->abfd) & EXEC_P) == 0
						&& (bfd_get_file_flags (aux->abfd) & DYNAMIC) == 0
						&& *relppp < relppend)
				{
					bfd_signed_vma distance_to_rel;

					distance_to_rel = (**relppp)->address
						- (rel_offset + addr_offset);

					/* Check to see if the current reloc is associated with
					   the instruction that we are about to disassemble.  */
					if (distance_to_rel == 0
							/* FIXME: This is wrong.  We are trying to catch
							   relocs that are addressed part way through the
							   current instruction, as might happen with a packed
							   VLIW instruction.  Unfortunately we do not know the
							   length of the current instruction since we have not
							   disassembled it yet.  Instead we take a guess based
							   upon the length of the previous instruction.  The
							   proper solution is to have a new target-specific
							   disassembler function which just returns the length
							   of an instruction at a given address without trying
							   to display its disassembly. */
							|| (distance_to_rel > 0
								&& distance_to_rel < (bfd_signed_vma) (previous_octets/ opb)))
					{
						inf->flags |= INSN_HAS_RELOC;
						aux->reloc = **relppp;
					}
				}

				octets = (*disassemble_fn) (section->vma + addr_offset, inf);
				if (insn_width == 0 && inf->bytes_per_line != 0)
					octets_per_line = inf->bytes_per_line;
				if (octets < (int) opb)
				{
					if (asmcode.pos){
						printf ("%s\n", asmcode.buffer);
					}
					if (octets >= 0)
					{
						bfd_nonfatal (_("disassemble_fn returned length"));
					}
					break;
				}
			}
			else
			{
				bfd_vma j;

				octets = octets_per_line;
				if (addr_offset + octets / opb > stop_offset)
					octets = (stop_offset - addr_offset) * opb;

				for (j = addr_offset * opb; j < addr_offset * opb + octets; ++j)
				{
					if (isprint (data[j]))
						buf[j - addr_offset * opb] = data[j];
					else
						buf[j - addr_offset * opb] = '.';
				}
				buf[j - addr_offset * opb] = '\0';
			}

			if (prefix_addresses
					? show_raw_insn > 0
					: show_raw_insn >= 0)
			{
				bfd_vma j;

				// If ! prefix_addresses and ! wide_output, we print
				//   octets_per_line octets per line. 
				pb = octets;
				if (pb > octets_per_line && ! prefix_addresses && ! wide_output)
					pb = octets_per_line;

				if (inf->bytes_per_chunk)
					bpc = inf->bytes_per_chunk;
				else
					bpc = 1;
			}

			if (! insns)
				printf ("\t%s", buf);
			else if (asmcode.pos) {
				sprintf_asmcode(data + addr_offset * opb, octets, section->vma+addr_offset, 
						&asmcode, codeblk, &bdumb);
			}

			if (!wide_output)
				(codeblk->sprintf) (codeblk, "\n");
			else
				need_nl = TRUE;
		}

		if (need_nl)
			(codeblk->sprintf) (codeblk, "\n");

		addr_offset += octets / opb;
	}
	inf->fprintf_func = (fprintf_ftype) fprintf;
	inf->stream = stdout;
	free (asmcode.buffer);
	aux->code->add_block(aux->code, codeblk);
}

	static void
disassemble_section (bfd *abfd, asection *section, void *inf)
{
	//const struct elf_backend_data * bed;
	bfd_vma                      sign_adjust = 0;
	struct disassemble_info *    pinfo = (struct disassemble_info *) inf;
	struct objdump_disasm_info * paux;
	unsigned int                 opb = pinfo->octets_per_byte;
	bfd_byte *                   data = NULL;
	bfd_size_type                datasize = 0;
	arelent **                   rel_pp = NULL;
	arelent **                   rel_ppstart = NULL;
	arelent **                   rel_ppend;
	unsigned long                stop_offset;
	asymbol *                    sym = NULL;
	long                         place = 0;
	long                         rel_count;
	bfd_vma                      rel_offset;
	unsigned long                addr_offset;

	/* Sections that do not contain machine
	   code are not normally disassembled.  */
	if (! disassemble_all
			&& ((section->flags & (SEC_CODE | SEC_HAS_CONTENTS))
				!= (SEC_CODE | SEC_HAS_CONTENTS)))
		return;

	datasize = bfd_get_section_size (section);
	if (datasize == 0)
		return;

	if (start_address == (bfd_vma) -1
			|| start_address < section->vma)
		addr_offset = 0;
	else
		addr_offset = start_address - section->vma;

	if (stop_address == (bfd_vma) -1)
		stop_offset = datasize / opb;
	else
	{
		if (stop_address < section->vma)
			stop_offset = 0;
		else
			stop_offset = stop_address - section->vma;
		if (stop_offset > datasize / opb)
			stop_offset = datasize / opb;
	}

	if (addr_offset >= stop_offset)
		return;

	/* Decide which set of relocs to use.  Load them if necessary.  */
	paux = (struct objdump_disasm_info *) pinfo->application_data;
	if (paux->dynrelbuf)
	{
		rel_pp = paux->dynrelbuf;
		rel_count = paux->dynrelcount;
		/* Dynamic reloc addresses are absolute, non-dynamic are section
		   relative.  REL_OFFSET specifies the reloc address corresponding
		   to the start of this section.  */
		rel_offset = section->vma;
	}
	else
	{
		rel_count = 0;
		rel_pp = NULL;
		rel_offset = 0;

		if ((section->flags & SEC_RELOC) != 0
				&& pinfo->disassembler_needs_relocs)
		{
			long relsize;

			relsize = bfd_get_reloc_upper_bound (abfd, section);
			if (relsize < 0)
				bfd_fatal (bfd_get_filename (abfd));

			if (relsize > 0)
			{
				rel_ppstart = rel_pp = (arelent **) xmalloc (relsize);
				rel_count = bfd_canonicalize_reloc (abfd, section, rel_pp, syms);
				if (rel_count < 0)
					bfd_fatal (bfd_get_filename (abfd));

				/* Sort the relocs by address.  */
				qsort (rel_pp, rel_count, sizeof (arelent *), compare_relocs);
			}
		}
	}
	rel_ppend = rel_pp + rel_count;

	data = (bfd_byte *) xmalloc (datasize);

	bfd_get_section_contents (abfd, section, data, 0, datasize);

	paux->sec = section;
	pinfo->buffer = data;
	pinfo->buffer_vma = section->vma;
	pinfo->buffer_length = datasize;
	pinfo->section = section;

	/* Skip over the relocs belonging to addresses below the
	   start address.  */
	while (rel_pp < rel_ppend
			&& (*rel_pp)->address < rel_offset + addr_offset)
		++rel_pp;

	//printf (_("\n//Disassembly of section %s:\n"), section->name);

	/* Find the nearest symbol forwards from our current position.  */
	paux->require_sec = TRUE;
	sym = (asymbol *) find_symbol_for_address (section->vma + addr_offset,
			(struct disassemble_info *) inf,
			&place);
	paux->require_sec = FALSE;

	/* PR 9774: If the target used signed addresses then we must make
	   sure that we sign extend the value that we calculate for 'addr'
	   in the loop below.  */
	/*if (bfd_get_flavour (abfd) == bfd_target_elf_flavour
	  && (bed = get_elf_backend_data (abfd)) != NULL
	  && bed->sign_extend_vma)
	  sign_adjust = (bfd_vma) 1 << (bed->s->arch_size - 1);*/

	/* Disassemble a block of instructions up to the address associated with
	   the symbol we have just found.  Then print the symbol and find the
	   next symbol on.  Repeat until we have disassembled the entire section
	   or we have reached the end of the address range we are interested in.  */
	while (addr_offset < stop_offset)
	{
		bfd_vma addr;
		asymbol *nextsym;
		unsigned long nextstop_offset;
		bfd_boolean insns;

		addr = section->vma + addr_offset;
		addr = ((addr & ((sign_adjust << 1) - 1)) ^ sign_adjust) - sign_adjust;

		if (sym != NULL && bfd_asymbol_value (sym) <= addr)
		{
			int x;

			for (x = place;
					(x < sorted_symcount
					 && (bfd_asymbol_value (sorted_syms[x]) <= addr));
					++x)
				continue;

			pinfo->symbols = sorted_syms + place;
			pinfo->num_symbols = x - place;
			pinfo->symtab_pos = place;
		}
		else
		{
			pinfo->symbols = NULL;
			pinfo->num_symbols = 0;
			pinfo->symtab_pos = -1;
		}

		/*if (! prefix_addresses)
		  {
		  pinfo->fprintf_func (pinfo->stream, "\n//");
		  objdump_print_addr_with_sym (abfd, section, sym, addr,
		  pinfo, FALSE);
		  pinfo->fprintf_func (pinfo->stream, ":\n");
		  }*/

		if (sym != NULL && bfd_asymbol_value (sym) > addr)
			nextsym = sym;
		else if (sym == NULL)
			nextsym = NULL;
		else
		{
#define is_valid_next_sym(SYM) \
			((SYM)->section == section \
			 && (bfd_asymbol_value (SYM) > bfd_asymbol_value (sym)) \
			 && pinfo->symbol_is_valid (SYM, pinfo))

			/* Search forward for the next appropriate symbol in
			   SECTION.  Note that all the symbols are sorted
			   together into one big array, and that some sections
			   may have overlapping addresses.  */
			while (place < sorted_symcount
					&& ! is_valid_next_sym (sorted_syms [place]))
				++place;

			if (place >= sorted_symcount)
				nextsym = NULL;
			else
				nextsym = sorted_syms[place];
		}

		if (sym != NULL && bfd_asymbol_value (sym) > addr)
			nextstop_offset = bfd_asymbol_value (sym) - section->vma;
		else if (nextsym == NULL)
			nextstop_offset = stop_offset;
		else
			nextstop_offset = bfd_asymbol_value (nextsym) - section->vma;

		if (nextstop_offset > stop_offset
				|| nextstop_offset <= addr_offset)
			nextstop_offset = stop_offset;

		/* If a symbol is explicitly marked as being an object
		   rather than a function, just dump the bytes without
		   disassembling them.  */
		if (disassemble_all
				|| sym == NULL
				|| sym->section != section
				|| bfd_asymbol_value (sym) > addr
				|| ((sym->flags & BSF_OBJECT) == 0
					&& (strstr (bfd_asymbol_name (sym), "gnu_compiled")
						== NULL)
					&& (strstr (bfd_asymbol_name (sym), "gcc2_compiled")
						== NULL))
				|| (sym->flags & BSF_FUNCTION) != 0)
			insns = TRUE;
		else
			insns = FALSE;

		disassemble_bytes (pinfo, paux->disassemble_fn, insns, data,
				addr_offset, nextstop_offset,
				rel_offset, &rel_pp, rel_ppend);

		addr_offset = nextstop_offset;
		sym = nextsym;
	}

	free (data);

	if (rel_ppstart != NULL)
		free (rel_ppstart);
}


/* Disassemble the contents of an object file.  */

	static void
disassemble_data (bfd *abfd, elf_asmcode_t *code, checker_ft patch_p)
{
	struct disassemble_info disasm_info;
	struct objdump_disasm_info aux;
	long i;

	/* We make a copy of syms to sort.  We don't want to sort syms
	   because that will screw up the relocs.  */
	sorted_symcount = symcount ? symcount : dynsymcount;
	sorted_syms = (asymbol **) xmalloc ((sorted_symcount + synthcount)
			* sizeof (asymbol *));
	memcpy (sorted_syms, symcount ? syms : dynsyms,
			sorted_symcount * sizeof (asymbol *));

	sorted_symcount = remove_useless_symbols (sorted_syms, sorted_symcount);

	for (i = 0; i < synthcount; ++i)
	{
		sorted_syms[sorted_symcount] = synthsyms + i;
		++sorted_symcount;
	}

	/* Sort the symbols into section and symbol order.  */
	qsort (sorted_syms, sorted_symcount, sizeof (asymbol *), compare_symbols);

	init_disassemble_info (&disasm_info, stdout, (fprintf_ftype) fprintf);

	disasm_info.application_data = (void *) &aux;
	aux.abfd = abfd;
	aux.require_sec = FALSE;
	aux.dynrelbuf = NULL;
	aux.dynrelcount = 0;
	aux.reloc = NULL;
	aux.code = code;
	aux.patch_blk_p = patch_p;

	disasm_info.print_address_func = objdump_print_address;
	disasm_info.symbol_at_address_func = objdump_symbol_at_address;

	if (machine != NULL)
	{
		const bfd_arch_info_type *inf = bfd_scan_arch (machine);

		if (inf == NULL)
			bfd_fatal (_("can't use supplied machinex"));

		abfd->arch_info = inf;
	}

	if (endian != BFD_ENDIAN_UNKNOWN)
	{
		struct bfd_target *xvec;

		xvec = (struct bfd_target *) xmalloc (sizeof (struct bfd_target));
		memcpy (xvec, abfd->xvec, sizeof (struct bfd_target));
		xvec->byteorder = endian;
		abfd->xvec = xvec;
	}

	/* Use libopcodes to locate a suitable disassembler.  */
	aux.disassemble_fn = disassembler (abfd);
	if (!aux.disassemble_fn)
	{
		bfd_nonfatal (_("can't disassemble for architecture"));
		return;
	}

	disasm_info.flavour = bfd_get_flavour (abfd);
	disasm_info.arch = bfd_get_arch (abfd);
	disasm_info.mach = bfd_get_mach (abfd);
	//Users can manually set this option according to "objdump -M" flag 
	disasm_info.disassembler_options = disassembler_options;
	disasm_info.octets_per_byte = bfd_octets_per_byte (abfd);
	disasm_info.skip_zeroes = DEFAULT_SKIP_ZEROES;
	disasm_info.skip_zeroes_at_end = DEFAULT_SKIP_ZEROES_AT_END;
	disasm_info.disassembler_needs_relocs = FALSE;

	if (bfd_big_endian (abfd))
		disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_BIG;
	else if (bfd_little_endian (abfd))
		disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_LITTLE;
	else
		/* ??? Aborting here seems too drastic.  We could default to big or little
		   instead.  */
		disasm_info.endian = BFD_ENDIAN_UNKNOWN;

	/* Allow the target to customize the info structure.  */
	disassemble_init_for_target (& disasm_info);

	disasm_info.symtab = sorted_syms;
	disasm_info.symtab_size = sorted_symcount;

	bfd_map_over_sections (abfd, disassemble_section, &disasm_info);

	if (aux.dynrelbuf != NULL)
		free (aux.dynrelbuf);
	free (sorted_syms);
}


bool patch_block_p (const void* rule, const void *_this)
{
	return false;
}

	elf_asmcode_t*
disasm_elf_file (char *elf_file, checker_ft patch_p, elf_cfi_t *cfi)
{
	struct stat statbuf;
	bfd *abfd;

	if ((stat (elf_file, &statbuf) < 0) ||
			!S_ISREG(statbuf.st_mode) ||
			(statbuf.st_size < 1))
	{
		return NULL;
	}

	//parse elf file based on bfd
	bfd_init();

	abfd = bfd_openr (elf_file, NULL);
	if (abfd == NULL) {
		return NULL;
	}

	disassemble = TRUE;
	disassemble_zeroes = FALSE;
	insn_width = 10;
	if (patch_p == NULL)
		patch_p = &patch_block_p;

	char **matching;
	elf_asmcode_t *code = (elf_asmcode_t*)xmalloc(
			sizeof(elf_asmcode_t));
	code->alloc = 100;
	code->ar = (asmcode_blk_t**)
		xmalloc(code->alloc * sizeof(asmcode_blk_t*));
	code->pos = 0;
	code->file = strdup(elf_file);
	code->add_block = (add_ft)elf_asmcode_add_block;
	code->sprintf = (sprintf_ft)elf_asmcode_printf;
	code->cfi = cfi;

	if (bfd_check_format_matches (abfd, bfd_object, &matching))
	{
		syms = slurp_symtab (abfd);

		if (bfd_get_dynamic_symtab_upper_bound (abfd) > 0)
			dynsyms = slurp_dynamic_symtab (abfd);

		synthcount = bfd_get_synthetic_symtab (abfd, symcount, syms,
				dynsymcount, dynsyms, &synthsyms);
		if (synthcount < 0)
			synthcount = 0;

		disassemble_data (abfd, code, patch_p);
	}

	bfd_close (abfd);

	return code;
}
