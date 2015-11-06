include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Iinsn -Wall -g -Werror
LDFLAGS = -lelf

TARGETS = create-diff-object kpatch-modpost
OBJS = create-diff-object.o kpatch-elf.o lookup.o insn/insn.o insn/inat.o
POSTOBJS = kpatch-modpost.o kpatch-elf.o
SOURCES = create-diff-object.c kpatch-modpost.c lookup.c insn/insn.c insn/inat.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

%.o : %.c
	$(CC) -MMD -MP $(CFLAGS) -c -o $@ $<

create-diff-object: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

kpatch-modpost: $(POSTOBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) kpatch-gcc $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)
	$(RM) $(BINDIR)/kpatch-build

clean:
	$(RM) $(TARGETS) $(OBJS) $(POSTOBJS) *.d insn/*.d
