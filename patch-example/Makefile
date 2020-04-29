.PHONY: all clean

CFLAGS=-ffunction-sections -fdata-sections -D_GNU_SOURCE -g
LDFLAGS=-lpthread

all: patch.o

patch.o: create-diff-object obj1-old.o obj1-new.o symtab Module.symvers
	./create-diff-object obj1-old.o obj1-new.o xy symtab Module.symvers patch patch.o

symtab: bin-old
	readelf -s bin-old > symtab

Module.symvers:
	@echo "Muss manuell erstellt werden (nicht löschen)"

bin-old: obj1-old.o main.o obj2.o wf-userland.o
	gcc -o $@ $^ ${LDFLAGS}

bin-new: obj1-new.o main.o obj2.o wf-userland.o
	gcc -o $@ $^ ${LDFLAGS}

%.o: %.c
	gcc ${CFLAGS} -c -o $@ $<

create-diff-object:
	${MAKE} -C ../kpatch/kpatch-build $@
	ln -sf ../kpatch/kpatch-build/$@

.PHONY: create-diff-object

clean:
	rm -rf bin-old bin-new symtab *.o
