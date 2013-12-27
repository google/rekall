obj-m += module.o
obj-m += pmem.o

KVER ?= $(shell uname -r)
KHEADER ?= /usr/src/linux-headers-$(KVER)

-include version.mk

all: dwarf pmem profile

pmem: pmem.c
	$(MAKE) -C $(KHEADER) M=$(PWD) modules

dwarf: module.c
	$(MAKE) -C $(KHEADER) CONFIG_DEBUG_INFO=y M=$(PWD) modules
	cp module.ko module_dwarf.ko

profile: module_dwarf.ko
	zip "`uname -r`.zip" module_dwarf.ko /boot/System.map-`uname -r`

clean:
	$(MAKE) -C $(KHEADER) M=$(PWD) clean
	rm -f module_dwarf.ko
