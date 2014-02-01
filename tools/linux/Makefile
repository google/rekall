obj-m += module.o
obj-m += pmem.o

KVER ?= $(shell uname -r)
KHEADER ?= /usr/src/linux-headers-$(KVER)
KSYSTEMMAP ?= /boot/System.map-$(KVER)
KCONFIG ?= /boot/config-$(KVER)

# Fedora Core
# KHEADER ?= /lib/modules/$(KVER)/source

# This needs to be specified because when running make under sudo we have no
# access to the PWD environment var.
PWD = `pwd`

-include version.mk

all: dwarf pmem profile

pmem: pmem.c
	$(MAKE) -C $(KHEADER) M=$(PWD) modules

dwarf: module.c
	$(MAKE) -C $(KHEADER) CONFIG_DEBUG_INFO=y M=$(PWD) modules
	cp module.ko module_dwarf.ko

profile: dwarf
	zip "$(KVER).zip" module_dwarf.ko $(KSYSTEMMAP) $(KCONFIG)

clean:
	$(MAKE) -C $(KHEADER) M=$(PWD) clean
	rm -f module_dwarf.ko
