obj-m += vmcs_layout.o

KVER ?= $(shell uname -r)
KHEADER ?= /usr/src/linux-headers-$(KVER)

# This needs to be specified because when running make under sudo we have no
# access to the PWD environment var.
PWD = `pwd`

-include version.mk

all: vmcs_layout

vmcs_layout: vmcs_layout.c
	$(MAKE) -C $(KHEADER) M=$(PWD) modules

clean:
	$(MAKE) -C $(KHEADER) M=$(PWD) clean
