all:
	gcc -g -Wall test.c -fms-extensions -o test.o
	rekal dwarfparser test.o --profile_class PDBProfile --output mspdb

clean:
	rm test.o mspdb
