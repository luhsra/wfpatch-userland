.PHONY: all clean

all: patch.o

patch.o: obj1-old.o obj1-new.o symtab Module.symvers
	./create-diff-object obj1-old.o obj1-new.o xy symtab Module.symvers patch patch.o

symtab: bin-old
	readelf -s bin-old > symtab

Module.symvers:
	@echo "Muss manuell erstellt werden (nicht löschen)"

bin-old: obj1-old.o obj2.o
	gcc -o $@ $^

bin-new: obj1-new.o obj2.o
	gcc -o $@ $^

%.o: %.c
	gcc -ffunction-sections -fdata-sections -c -o $@ $<

clean:
	rm -rf obj1-old.o obj1-new.o obj2.o bin-old bin-new symtab patch.o
