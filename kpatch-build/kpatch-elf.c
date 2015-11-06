#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "kpatch-elf.h"

enum loglevel loglevel = NORMAL;

char *status_str(enum status status)
{
	switch(status) {
	case NEW:
		return "NEW";
	case CHANGED:
		return "CHANGED";
	case SAME:
		return "SAME";
	default:
		ERROR("status_str");
	}
	/* never reached */
	return NULL;
}

void kpatch_dump_kelf(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	struct rela *rela;

	struct list_head *rela_list;

	if (loglevel > DEBUG)
		return;

	printf("\n=== Sections ===\n");
	list_for_each_entry(sec, &kelf->sections, list) {
		printf("%02d %s (%s)", sec->index, sec->name, status_str(sec->status));
		if (is_rela_section(sec)) {
			printf(", base-> %s\n", sec->base->name);
			/* skip .debug_* sections */
			if (is_debug_section(sec))
				goto next;
			printf("rela section expansion\n");
			rela_list = &sec->relas;
			list_for_each_entry(rela, rela_list, list) {
				printf("sym %d, offset %d, type %d, %s %s %d\n",
				       rela->sym->index, rela->offset,
				       rela->type, rela->sym->name,
				       (rela->addend < 0)?"-":"+",
				       abs(rela->addend));
			}
		} else {
			if (is_klp_rela_section(sec))
				goto next;
			if (sec->sym)
				printf(", sym-> %s", sec->sym->name);
			if (sec->secsym)
				printf(", secsym-> %s", sec->secsym->name);
			if (sec->rela)
				printf(", rela-> %s", sec->rela->name);
		}
next:
		printf("\n");
	}

	printf("\n=== Symbols ===\n");
	list_for_each_entry(sym, &kelf->symbols, list) {
		printf("sym %02d, type %d, bind %d, ndx %02d, name %s (%s)",
			sym->index, sym->type, sym->bind, sym->sym.st_shndx,
			sym->name, status_str(sym->status));
		if (sym->sec && (sym->type == STT_FUNC || sym->type == STT_OBJECT))
			printf(" -> %s", sym->sec->name);
		printf("\n");
	}
}

int is_klp_symbol(struct symbol *sym)
{
	return (strstr(sym->name, ".klp.") != NULL) && sym->type != STT_SECTION;
}

int is_external_symbol(struct symbol *sym)
{
	int len;
	int lensuffix;
	char *suffix;

	suffix = ".ext";
	len = strlen(sym->name);
	lensuffix = strlen(suffix);

	return strncmp(sym->name + (len - lensuffix), suffix, lensuffix) == 0;
}

int is_rela_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_RELA);
}

int is_klp_rela_section(struct section *sec) 
{
	//return (sec->sh.sh_type == SHT_RELA_LIVEPATCH);
	return (!strncmp("__klp_rela", sec->name, 10));
}

int is_text_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_PROGBITS &&
		(sec->sh.sh_flags & SHF_EXECINSTR));
}

int is_debug_section(struct section *sec)
{
	char *name;
	if (is_rela_section(sec))
		name = sec->base->name;
	else
		name = sec->name;
	return !strncmp(name, ".debug_", 7);
}

struct section *find_section_by_index(struct list_head *list, unsigned int index)
{
	struct section *sec;

	list_for_each_entry(sec, list, list)
		if (sec->index == index)
			return sec;

	return NULL;
}

struct section *find_section_by_name(struct list_head *list, const char *name)
{
	struct section *sec;

	list_for_each_entry(sec, list, list)
		if (!strcmp(sec->name, name))
			return sec;

	return NULL;
}

struct symbol *find_symbol_by_index(struct list_head *list, size_t index)
{
	struct symbol *sym;

	list_for_each_entry(sym, list, list)
		if (sym->index == index)
			return sym;

	return NULL;
}

int is_bundleable(struct symbol *sym)
{
	if (sym->type == STT_FUNC &&
	    !strncmp(sym->sec->name, ".text.",6) &&
	    !strcmp(sym->sec->name + 6, sym->name))
		return 1;

	if (sym->type == STT_FUNC &&
	    !strncmp(sym->sec->name, ".text.unlikely.",15) &&
	    !strcmp(sym->sec->name + 15, sym->name))
		return 1;

	if (sym->type == STT_OBJECT &&
	   !strncmp(sym->sec->name, ".data.",6) &&
	   !strcmp(sym->sec->name + 6, sym->name))
		return 1;

	if (sym->type == STT_OBJECT &&
	   !strncmp(sym->sec->name, ".rodata.",8) &&
	   !strcmp(sym->sec->name + 8, sym->name))
		return 1;

	if (sym->type == STT_OBJECT &&
	   !strncmp(sym->sec->name, ".bss.",5) &&
	   !strcmp(sym->sec->name + 5, sym->name))
		return 1;

	return 0;
}


struct symbol *find_symbol_by_name(struct list_head *list, const char *name)
{
	struct symbol *sym;

	list_for_each_entry(sym, list, list)
		if (sym->name && !strcmp(sym->name, name))
			return sym;

	return NULL;
}

int find_symbol_by_name_ndx(struct list_head *list, const char *name)
{
	struct symbol *sym;

	list_for_each_entry(sym, list, list)
		if (sym->name && !strcmp(sym->name, name))
			return sym->index;
	return 0;
}

void print_strtab(char *buf, size_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (buf[i] == 0)
			printf("\\0");
		else
			printf("%c",buf[i]);
	}
}

void kpatch_create_shstrtab(struct kpatch_elf *kelf)
{
	struct section *shstrtab, *sec;
	size_t size, offset, len;
	char *buf;

	shstrtab = find_section_by_name(&kelf->sections, ".shstrtab");
	if (!shstrtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	size = 1; /* for initial NULL terminator */
	list_for_each_entry(sec, &kelf->sections, list)
		size += strlen(sec->name) + 1; /* include NULL terminator */

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	offset = 1;
	list_for_each_entry(sec, &kelf->sections, list) {
		len = strlen(sec->name) + 1;
		sec->sh.sh_name = offset;
		memcpy(buf + offset, sec->name, len);
		offset += len;
	}

	if (offset != size)
		ERROR("shstrtab size mismatch");

	shstrtab->data->d_buf = buf;
	shstrtab->data->d_size = size;

	if (loglevel <= DEBUG) {
		printf("shstrtab: ");
		print_strtab(buf, size);
		printf("\n");

		list_for_each_entry(sec, &kelf->sections, list)
			printf("%s @ shstrtab offset %d\n",
			       sec->name, sec->sh.sh_name);
	}
}


void kpatch_create_strtab(struct kpatch_elf *kelf)
{
	struct section *strtab;
	struct symbol *sym;
	size_t size = 0, offset = 0, len;
	char *buf;

	strtab = find_section_by_name(&kelf->sections, ".strtab");
	if (!strtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_SECTION)
			continue;
		size += strlen(sym->name) + 1; /* include NULL terminator */
	}

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_SECTION) {
			sym->sym.st_name = 0;
			continue;
		}
		len = strlen(sym->name) + 1;
		sym->sym.st_name = offset;
		memcpy(buf + offset, sym->name, len);
		offset += len;
	}

	if (offset != size)
		ERROR("shstrtab size mismatch");

	strtab->data->d_buf = buf;
	strtab->data->d_size = size;

	if (loglevel <= DEBUG) {
		printf("strtab: ");
		print_strtab(buf, size);
		printf("\n");

		list_for_each_entry(sym, &kelf->symbols, list)
			printf("%s @ strtab offset %d\n",
			       sym->name, sym->sym.st_name);
	}
}

void kpatch_create_symbol_list(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct symbol *sym;
	int symbols_nr, index = 0;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("missing symbol table");

	symbols_nr = symtab->sh.sh_size / symtab->sh.sh_entsize;

	log_debug("\n=== symbol list (%d entries) ===\n", symbols_nr);

	while (symbols_nr--) {
		ALLOC_LINK(sym, &kelf->symbols);

		sym->index = index;
		if (!gelf_getsym(symtab->data, index, &sym->sym))
			ERROR("gelf_getsym");
		index++;

		sym->name = elf_strptr(kelf->elf, symtab->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name)
			ERROR("elf_strptr");

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);

		if (sym->sym.st_shndx > SHN_UNDEF &&
		    sym->sym.st_shndx < SHN_LORESERVE) {
			sym->sec = find_section_by_index(&kelf->sections,
					sym->sym.st_shndx);
			if (!sym->sec)
				ERROR("couldn't find section for symbol %s\n",
					sym->name);

			if (is_bundleable(sym)) {
				if (sym->sym.st_value != 0)
					ERROR("symbol %s at offset %lu within section %s, expected 0",
					      sym->name, sym->sym.st_value, sym->sec->name);
				sym->sec->sym = sym;
			} else if (sym->type == STT_SECTION) {
				sym->sec->secsym = sym;
				/* use the section name as the symbol name */
				sym->name = sym->sec->name;
			}
		}

		log_debug("sym %02d, type %d, bind %d, ndx %02d, name %s",
			sym->index, sym->type, sym->bind, sym->sym.st_shndx,
			sym->name);
		if (sym->sec)
			log_debug(" -> %s", sym->sec->name);
		log_debug("\n");
	}

}

void kpatch_create_rela_list(struct kpatch_elf *kelf, struct section *sec)
{
	int rela_nr, index = 0, skip = 0;
	struct rela *rela;
	unsigned int symndx;

	/* find matching base (text/data) section */
	if (is_klp_rela_section(sec))
		sec->base = find_section_by_name(&kelf->sections, strchr(sec->name, '.'));
	else
		sec->base = find_section_by_name(&kelf->sections, sec->name + 5);

	if (!sec->base)
		ERROR("can't find base section for rela section %s", sec->name);

	/* create reverse link from base section to this rela section */
	sec->base->rela = sec;

	rela_nr = sec->sh.sh_size / sec->sh.sh_entsize;

	log_debug("\n=== rela list for %s (%d entries) ===\n",
		sec->base->name, rela_nr);

	if (is_debug_section(sec)) {
		log_debug("skipping rela listing for .debug_* section\n");
		skip = 1;
	}

	/* read and store the rela entries */
	while (rela_nr--) {
		ALLOC_LINK(rela, &sec->relas);

		if (!gelf_getrela(sec->data, index, &rela->rela))
			ERROR("gelf_getrela");
		index++;

		rela->type = GELF_R_TYPE(rela->rela.r_info);
		rela->addend = rela->rela.r_addend;
		rela->offset = rela->rela.r_offset;
		symndx = GELF_R_SYM(rela->rela.r_info);
		rela->sym = find_symbol_by_index(&kelf->symbols, symndx);
		if (!rela->sym)
			ERROR("could not find rela entry symbol\n");
		if (rela->sym->sec &&
		    (rela->sym->sec->sh.sh_flags & SHF_STRINGS)) {
			rela->string = rela->sym->sec->data->d_buf + rela->addend;
			if (!rela->string)
				ERROR("could not lookup rela string for %s+%d",
				      rela->sym->name, rela->addend);
		}

		if (skip)
			continue;
		log_debug("offset %d, type %d, %s %s %d", rela->offset,
			rela->type, rela->sym->name,
			(rela->addend < 0)?"-":"+", abs(rela->addend));
		if (rela->string)
			log_debug(" (string = %s)", rela->string);
		log_debug("\n");
	}
}


void kpatch_create_section_list(struct kpatch_elf *kelf)
{
	Elf_Scn *scn = NULL;
	struct section *sec;
	size_t shstrndx, sections_nr;

	if (elf_getshdrnum(kelf->elf, &sections_nr))
		ERROR("elf_getshdrnum");

	/*
	 * elf_getshdrnum() includes section index 0 but elf_nextscn
	 * doesn't return that section so subtract one.
	 */
	sections_nr--;

	if (elf_getshdrstrndx(kelf->elf, &shstrndx))
		ERROR("elf_getshdrstrndx");

	log_debug("=== section list (%zu) ===\n", sections_nr);

	while (sections_nr--) {
		ALLOC_LINK(sec, &kelf->sections);

		scn = elf_nextscn(kelf->elf, scn);
		if (!scn)
			ERROR("scn NULL");

		if (!gelf_getshdr(scn, &sec->sh))
			ERROR("gelf_getshdr");

		sec->name = elf_strptr(kelf->elf, shstrndx, sec->sh.sh_name);
		if (!sec->name)
			ERROR("elf_strptr");

		sec->data = elf_getdata(scn, NULL);
		if (!sec->data)
			ERROR("elf_getdata");

		sec->index = elf_ndxscn(scn);

		log_debug("ndx %02d, data %p, size %zu, name %s\n",
			sec->index, sec->data->d_buf, sec->data->d_size,
			sec->name);
	}

	/* Sanity check, one more call to elf_nextscn() should return NULL */
	if (elf_nextscn(kelf->elf, scn))
		ERROR("expected NULL");
}


void kpatch_check_program_headers(Elf *elf)
{
	size_t ph_nr;

	if (elf_getphdrnum(elf, &ph_nr))
		ERROR("elf_getphdrnum");

	if (ph_nr != 0)
		DIFF_FATAL("ELF contains program header");
}

/* Check which functions have fentry calls; save this info for later use. */
static void kpatch_find_fentry_calls(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	struct rela *rela;
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type != STT_FUNC
		    || !(sym->sym.st_shndx > SHN_UNDEF &&
		    sym->sym.st_shndx < SHN_LORESERVE)
		    || !sym->sec->rela)
			continue;

		rela = list_first_entry(&sym->sec->rela->relas, struct rela,
					list);
		if (rela->type != R_X86_64_NONE ||
		    strcmp(rela->sym->name, "__fentry__"))
			continue;

		sym->has_fentry_call = 1;
	}
}


struct kpatch_elf *kpatch_elf_open(const char *name)
{
	Elf *elf;
	int fd;
	struct kpatch_elf *kelf;
	struct section *sec;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		ERROR("open");

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		ERROR("elf_begin");

	kelf = malloc(sizeof(*kelf));
	if (!kelf)
		ERROR("malloc");
	memset(kelf, 0, sizeof(*kelf));
	INIT_LIST_HEAD(&kelf->sections);
	INIT_LIST_HEAD(&kelf->symbols);
	INIT_LIST_HEAD(&kelf->strings);

	/* read and store section, symbol entries from file */
	kelf->elf = elf;
	kelf->fd = fd;
	kpatch_create_section_list(kelf);
	kpatch_create_symbol_list(kelf);

	/* for each rela section, read and store the rela entries */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec))
			continue;
		INIT_LIST_HEAD(&sec->relas);
		kpatch_create_rela_list(kelf, sec);
	}

	kpatch_find_fentry_calls(kelf);
	return kelf;
}

void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile)
{
	int fd;
	struct section *sec;
	Elf *elfout;
	GElf_Ehdr eh, ehout;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh;

	/* TODO make this argv */
	fd = creat(outfile, 0777);
	if (fd == -1)
		ERROR("creat");

	elfout = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!elfout)
		ERROR("elf_begin");

	if (!gelf_newehdr(elfout, gelf_getclass(kelf->elf)))
		ERROR("gelf_newehdr");

	if (!gelf_getehdr(elfout, &ehout))
		ERROR("gelf_getehdr");

	if (!gelf_getehdr(elf, &eh))
		ERROR("gelf_getehdr");

	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = eh.e_ident[EI_DATA];
	ehout.e_machine = eh.e_machine;
	ehout.e_type = eh.e_type;
	ehout.e_version = EV_CURRENT;
	ehout.e_shstrndx = find_section_by_name(&kelf->sections, ".shstrtab")->index;

	/* add changed sections */
	list_for_each_entry(sec, &kelf->sections, list) {
		scn = elf_newscn(elfout);
		if (!scn)
			ERROR("elf_newscn");

		data = elf_newdata(scn);
		if (!data)
			ERROR("elf_newdata");

		if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY))
			ERROR("elf_flagdata");

		data->d_type = sec->data->d_type;
		data->d_buf = sec->data->d_buf;
		data->d_size = sec->data->d_size;

		if(!gelf_getshdr(scn, &sh))
			ERROR("gelf_getshdr");

		sh = sec->sh;

		if (!gelf_update_shdr(scn, &sh))
			ERROR("gelf_update_shdr");
	}

	if (!gelf_update_ehdr(elfout, &ehout))
		ERROR("gelf_update_ehdr");

	if (elf_update(elfout, ELF_C_WRITE) < 0) {
		printf("%s\n",elf_errmsg(-1));
		ERROR("elf_update");
	}
}

void kpatch_create_symtab(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct symbol *sym;
	char *buf;
	size_t size;
	int nr = 0, offset = 0, nr_local = 0;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("find_section_by_name");

	/* count symbols */
	list_for_each_entry(sym, &kelf->symbols, list)
		nr++;

	/* create new symtab buffer */
	size = nr * symtab->sh.sh_entsize;
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	offset = 0;
	list_for_each_entry(sym, &kelf->symbols, list) {
		memcpy(buf + offset, &sym->sym, symtab->sh.sh_entsize);
		offset += symtab->sh.sh_entsize;

		if (is_local_sym(sym))
			nr_local++;
	}

	symtab->data->d_buf = buf;
	symtab->data->d_size = size;

	/* update symtab section header */
	symtab->sh.sh_link = find_section_by_name(&kelf->sections, ".strtab")->index;
	symtab->sh.sh_info = nr_local;
}

int is_null_sym(struct symbol *sym)
{
	return !strlen(sym->name);
}

int is_file_sym(struct symbol *sym)
{
	return sym->type == STT_FILE;
}

int is_local_func_sym(struct symbol *sym)
{
	return sym->bind == STB_LOCAL && sym->type == STT_FUNC;
}

int is_local_sym(struct symbol *sym)
{
	return sym->bind == STB_LOCAL;
}
