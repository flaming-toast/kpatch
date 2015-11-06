#include "kpatch-elf.h"
#include <string.h>
#include <stdlib.h>
#include <argp.h>

struct arguments {
	char *args[2];
	int debug;
};

static char args_doc[] = "module.o output.o";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
	{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	   know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'd':
			arguments->debug = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 2)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 2)
				/* Not enough arguments. */
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, 0 };

void unpack_klp_relasecs(struct kpatch_elf *kelf)
{
	int nr, symndx, offset, new_size, i = 0;
	char *buf;
	GElf_Rela *rela;
	struct klp_rela *klp_rela;
	GElf_Rela *gelf_rela;
	struct section *sec;
	unsigned long r_info;

	list_for_each_entry(sec, &kelf->sections, list) {
		if(!is_klp_rela_section(sec))
			continue;
		offset = 0;
		nr = sec->data->d_size / sizeof(struct klp_rela);
		new_size = nr * sizeof(GElf_Rela);
		buf = malloc(new_size);
		klp_rela = sec->data->d_buf;
		if (!buf)
			ERROR("malloc");
		for(i = 0; i < nr; i++) {
			symndx = find_symbol_by_name_ndx(&kelf->symbols,
							 klp_rela[i].symname);
			if (!symndx)
				ERROR("unpack_klp_relasecs: could not find symbol corresponding to klp rela");
			rela = &klp_rela[i].rela;
			memcpy(buf + offset, &(klp_rela[i].rela),sizeof(GElf_Rela));
			gelf_rela = (GElf_Rela *)(buf + offset);
			r_info = GELF_R_INFO(symndx, GELF_R_TYPE(rela->r_info));
			memcpy(&gelf_rela->r_info, &r_info, sizeof(unsigned long));
			offset += sizeof(GElf_Rela);
		}
		sec->data->d_buf = buf;
		sec->data->d_size = new_size;
	}
}

void post_restore_sht_rela(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct section *symtab;

	symtab = find_section_by_name(&kelf->sections, ".symtab");

	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_klp_rela_section(sec))
			continue;
		sec->base = find_section_by_name(&kelf->sections,
						 strchr(sec->name, '.'));
		sec->sh.sh_type = SHT_RELA;
		sec->sh.sh_flags = sec->sh.sh_flags & ~SHF_ALLOC;
		sec->sh.sh_flags |= SHF_RELA_LIVEPATCH;
		sec->sh.sh_flags |= SHF_INFO_LINK;
		sec->data->d_type = ELF_T_RELA;
		sec->sh.sh_entsize = sizeof(GElf_Rela);
		sec->sh.sh_info = sec->base->index;
		sec->sh.sh_link = symtab->index;
	}
}

void post_mark_shndx(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	char *buf, *ptr;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (is_external_symbol(sym))
			sym->sym.st_info = GELF_ST_INFO(STB_LIVEPATCH_EXT,
							GELF_ST_TYPE(sym->sym.st_info));
		if (is_klp_symbol(sym)) {
			sym->sym.st_shndx = SHN_LIVEPATCH;
			buf = strdup(sym->name);
			ptr = strstr(buf, ".klp.");
			*ptr = '\0';
			sym->name = strdup(buf);
		}
	}
}

int main(int argc, char *argv[])
{
	struct kpatch_elf *kelf;
	struct arguments arguments;

	arguments.debug = 0;
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	elf_version(EV_CURRENT);

	kelf = kpatch_elf_open(arguments.args[0]);


	unpack_klp_relasecs(kelf);
	struct section *sec;
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_klp_rela_section(sec))
			continue;
	}
	post_restore_sht_rela(kelf);
	post_mark_shndx(kelf);

	kpatch_create_shstrtab(kelf);
	kpatch_create_strtab(kelf);
	kpatch_create_symtab(kelf);

	kpatch_write_output_elf(kelf, kelf->elf, arguments.args[1]);

}
