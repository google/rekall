obj-m += module.o

KDIR ?= /
KVER ?= $(shell uname -r)

-include version.mk

all:: version.h
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build CONFIG_DEBUG_INFO=y M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) clean
	-rm -f version.h

version.h : 
	@echo "" >> version.h
