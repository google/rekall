all:
	gcc -g -Wall test.c -fms-extensions -o test.o
	rekal dwarfparser test.o > vtypes.json
	zip mspdb.zip vtypes.json metadata test.c \
	    sbs_sdk/include/pdb_info.h sbs_pdb/sbs_pdb.h

clean:
	rm mspdb.zip test.o vtypes.json
