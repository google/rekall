# MacPmem - OS X Physical Memory Access

MacPmem enables read/write access to physical memory on OS X 10.8 through
10.11. It simultaneously exposes a wealth of useful information about the
operating system and hardware it's running on through a informational device and
sysctl interface.

It exposes two devices:

 - /dev/pmem  # Physical memory read access (can be built with write support).
 - /dev/pmem_info  # Informational dump.

## Quick Example

	> sudo kextload MacPmem.kext
	> sudo cat /dev/pmem_info

	# Outputs:
	# %YAML 1.2
	# ---
	# meta:
	#   pmem_api_version: 2
	#   cr3: 5773611222
	#   dtb_off: 5773611008
	#   phys_mem_size: 17179869184
	#   pci_config_space_base: 3758096384
	#   mmap_poffset: 353394688
	#   mmap_desc_version: 1
	#   mmap_size: 11856
	#   mmap_desc_size: 48
	#   kaslr_slide: 304087040
	#   kernel_poffset: 305135616
	#   kernel_version: "Darwin Kernel Version 14.4.0: Thu May 28 11:35:04 PDT 2015; root:xnu-2782.30.5~1/RELEASE_X86_64"
	#   version_poffset: 313959808

	> sudo xxd -s 313959808 /dev/pmem | head

	# Outputs:
	# 12b6a580:4461 7277 696e 204b 6572 6e65 6c20 5665  Darwin Kernel Ve
	# 12b6a590:7273 696f 6e20 3134 2e34 2e30 3a20 5468  rsion 14.4.0: Th
	# 12b6a5a0:7520 4d61 7920 3238 2031 313a 3335 3a30  u May 28 11:35:0
	# 12b6a5b0:3420 5044 5420 3230 3135 3b20 726f 6f74  4 PDT 2015; root
	# 12b6a5c0:3a78 6e75 2d32 3738 322e 3330 2e35 7e31  :xnu-2782.30.5~1
	# 12b6a5d0:2f52 454c 4541 5345 5f58 3836 5f36 3400  /RELEASE_X86_64.
	# 12b6a5e0:0e00 0000 0400 0000 0000 0000 8000 0000  ................
	# 12b6a5f0:0000 0000 3000 726f 6f74 0031 342e 342e  ....0.root.14.4.
	# 12b6a600:3000 4461 7277 696e 0000 0000 0000 0000  0.Darwin........
	# 12b6a610:0000 0000 0100 0000 0200 0000 0300 0000  ................

	> sudo rekall -f /dev/pmem  # Analyze the running memory of my own system.

## SYSCTL controls

### Logging level

	# Enable debug logging.
	> sudo sysctl -w kern.pmem_logging=4

	# Set to warn-level logging (default).
	> sudo sysctl -w kern.pmem_logging=2

### Read/write safety

By default, IO operations to /dev/pmem will silently fail (return zeros) for any
reads or writes to parts of memory marked as inaccessible by the EFI. The EFI
creates a physical memory map early in the boot process for the bootloader and
the kernel to interpret. This map demarks regions that are physically damaged,
backed by a PCI device (as opposed to RAM) or otherwise deserving special
consideration.

	# Disable read/write safety.
	> sudo sysctl -w kern.pmem_allow_unsafe_operations=1

	# Re-enable read/write safety.
	> sudo sysctl -w kern.pmem_allow_unsafe_operations=0
