
#include <sys/stat.h>
#include <fcntl.h>
#include <gelf.h>
#include <error.h>
#include "list.h"

/* We mark __klp_rela sections with SHF_LIVEPATCH
 * and klp symbols with STT_LIVEPATCH
 */
#define SHF_RELA_LIVEPATCH 0x4000000
#define STT_LIVEPATCH 11
#define SHT_RELA_LIVEPATCH 0x60000000
#define SHN_LIVEPATCH 0xff21
#define STB_LIVEPATCH_EXT 11

#define KSYM_NAME_LEN 256

enum loglevel {
	DEBUG,
	NORMAL
};

extern enum loglevel loglevel;

char *childobj;

#define log(level, format, ...) \
({ \
	if (loglevel <= (level)) \
		printf(format, ##__VA_ARGS__); \
})
#define log_debug(format, ...) log(DEBUG, format, ##__VA_ARGS__)
#define log_normal(format, ...) log(NORMAL, "%s: " format, childobj, ##__VA_ARGS__)

#define ERROR(format, ...) \
	error(1, 0, "ERROR: %s: %s: %d: " format, childobj, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DIFF_FATAL(format, ...) \
({ \
	fprintf(stderr, "ERROR: %s: " format "\n", childobj, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})

#define ALLOC_LINK(_new, _list) \
{ \
	(_new) = malloc(sizeof(*(_new))); \
	if (!(_new)) \
		ERROR("malloc"); \
	memset((_new), 0, sizeof(*(_new))); \
	INIT_LIST_HEAD(&(_new)->list); \
	list_add_tail(&(_new)->list, (_list)); \
}

enum status {
	NEW,
	CHANGED,
	SAME
};

struct section {
	struct list_head list;
	struct section *twin;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	int index;
	enum status status;
	int include;
	int ignore;
	int grouped;
	int tag;
	union {
		struct { /* if (is_rela_section()) */
			struct section *base;
			struct list_head relas;
			struct list_head klp_relas;
			int has_klp_relas;
		};
		struct { /* else */
			struct section *rela;
			struct section *klp_rela;
			struct symbol *secsym, *sym;
		};
	};
};

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	int index;
	int tag;
	int external;
	unsigned char bind, type;
	enum status status;
	int include; /* used in the patched elf */
	int has_fentry_call;
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	int external;
	int addend;
	int offset;
	char *string;
};

struct klp_rela {
	GElf_Rela rela;
	char symname[KSYM_NAME_LEN];
};

struct kpatch_elf {
	Elf *elf;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
	int fd;
};

extern struct kpatch_elf *kpatch_elf_open(const char *name);
extern void kpatch_check_program_headers(Elf *elf);
extern void kpatch_create_section_list(struct kpatch_elf *kelf);
extern void kpatch_create_rela_list(struct kpatch_elf *kelf, struct section *sec);
extern void kpatch_create_symbol_list(struct kpatch_elf *kelf);
extern struct symbol *find_symbol_by_name(struct list_head *list, const char *name);
extern int find_symbol_by_name_ndx(struct list_head *list, const char *name);
extern struct section *find_section_by_index(struct list_head *list, unsigned int index);
extern struct section *find_section_by_name(struct list_head *list, const char *name);
extern struct symbol *find_symbol_by_index(struct list_head *list, size_t index);
extern struct symbol *find_symbol_by_name(struct list_head *list, const char *name);
extern int is_bundleable(struct symbol *sym);

extern int is_klp_symbol(struct symbol *sym);
extern int is_external_symbol(struct symbol *sym);
extern int is_rela_section(struct section *sec);
extern int is_klp_rela_section(struct section *sec);
extern int is_text_section(struct section *sec);
extern int is_debug_section(struct section *sec);

extern void kpatch_dump_kelf(struct kpatch_elf *kelf);
extern void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile);

extern char *status_str(enum status status);

extern void kpatch_create_symtab(struct kpatch_elf *kelf);
extern void kpatch_create_strtab(struct kpatch_elf *kelf);
extern void kpatch_create_shstrtab(struct kpatch_elf *kelf);


extern int is_local_sym(struct symbol *sym);
extern int is_local_func_sym(struct symbol *sym);
extern int is_file_sym(struct symbol *sym);
extern int is_null_sym(struct symbol *sym);
