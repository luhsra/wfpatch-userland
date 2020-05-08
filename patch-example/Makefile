.PHONY: all clean

CFLAGS=-ffunction-sections -fdata-sections  -g -fPIE -fPIC -Wa,-mrelax-relocations=no
LDFLAGS=-lpthread -ldl

all: patch-obj1.o patch-obj2.o bin-new

patch-obj1.o: bin-old obj1-old.o obj1-new.o
	../create-patch bin-old --obj obj1-old.o obj1-new.o

patch-obj2.o: bin-old obj2-old.o obj2-new.o
	../create-patch bin-old --obj obj2-old.o obj2-new.o

run: bin-old patch-obj1.o
	WF_PATCH_QUEUE="patch-obj1.o;patch-obj2.o" ./bin-old

bin-old: obj1-old.o main.o obj2-old.o wf-userland.o
	gcc -o $@ $^ ${LDFLAGS}

bin-new: obj1-new.o main.o obj2-new.o wf-userland.o
	gcc -o $@ $^ ${LDFLAGS}

%.o: %.c
	gcc ${CFLAGS} -c -o $@ $<

%.S: %.c
	gcc ${CFLAGS} -S -o $@ $<

create-diff-object:
	${MAKE} -C ../kpatch/kpatch-build $@
	ln -sf ../kpatch/kpatch-build/$@

.PHONY: create-diff-object

clean:
	rm -rf bin-old bin-new symtab *.o
