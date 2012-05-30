obj-m += module.o
obj-m += pmem.o

KDIR ?= /
KVER ?= $(shell uname -r)

-include version.mk

all: dwarf pmem

pmem: pmem.c
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) modules

dwarf: module.c
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build CONFIG_DEBUG_INFO=y M=$(PWD) modules
	cp module.ko module_dwarf.ko

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) clean
	rm -f module_dwarf.ko
