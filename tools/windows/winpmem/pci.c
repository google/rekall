#include "pci.h"



u32 read_pci_config(u8 bus, u8 slot, u8 func, u8 offset) {
  u32 v;
  __outdword(PCI_CONFIG_ADDRESS,
	     0x80000000 | (bus<<16) | (slot<<11) | (func<<8) | offset);
  v = __indword(PCI_CONFIG_DATA);
  return v;
}

void write_pci_config(u8 bus, u8 slot, u8 func, u8 offset, u32 value) {
  __outdword(PCI_CONFIG_ADDRESS,
	     0x80000000 | (bus<<16) | (slot<<11) | (func<<8) | offset);
  __outdword(PCI_CONFIG_DATA, value);
}

void write_pci_config_16(u8 bus, u8 slot, u8 func, u8 offset, u16 value) {
  __outdword(PCI_CONFIG_ADDRESS,
	     0x80000000 | (bus<<16) | (slot<<11) | (func<<8) | offset);
  __outword(PCI_CONFIG_DATA, value);
}
u8 read_pci_config_byte(u8 bus, u8 slot, u8 func, u8 offset) {
  u8 v;
  __outdword(PCI_CONFIG_ADDRESS,
	     0x80000000 | (bus<<16) | (slot<<11) | (func<<8) | offset);
  v = __inbyte(PCI_CONFIG_DATA + (offset&3));
  return v;
}

u16 read_pci_config_16(u8 bus, u8 slot, u8 func, u8 offset) {
  u16 v;
  __outdword(PCI_CONFIG_ADDRESS,
	     0x80000000 | (bus<<16) | (slot<<11) | (func<<8) | offset);
  v = __inword(PCI_CONFIG_DATA + (offset&2));
  return v;
}

u32 get_base_register_size(u8 bus, u8 slot, u8 func, u8 offset) {
  __int32 base = read_pci_config(bus, slot, func, offset);
  u32 mask = 0;
  u16 command =0;

  if (base == 0) return 0;

  command = read_pci_config_16(bus, slot, func, PCI_COMMAND);

  // Disable IO and memory bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, 0);

  // Write to config space all 0xFFFFFFFF
  write_pci_config(bus, slot, func, offset, 0xFFFFFFFF);
  mask = read_pci_config(bus, slot, func, offset) & 0xFFFFFFF0;
  write_pci_config(bus, slot, func, offset, base);

  // Reenable bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, command);

  return ~mask + base;
};


#if WINPMEM_PCI_DEBUG
// Debugging functions for dumping out PCI configuration data.

void dump_interesting_fields(u8 bus, u8 slot, u8 func) {
  u16 vendor_id = read_pci_config_16(bus, slot, func, PCI_VENDOR_ID);
  u16 device_id = read_pci_config_16(bus, slot, func, PCI_DEVICE_ID);

  WinDbgPrint("pci 0000:%02x:%02x.%d  ", bus, slot, func);
  WinDbgPrint("Id %04x:%04x config space:\n", vendor_id, device_id);
};

void dump_bar(u8 bus, u8 slot, u8 func) {
  u16 vendor_id = read_pci_config_16(bus, slot, func, PCI_VENDOR_ID);
  u16 device_id = read_pci_config_16(bus, slot, func, PCI_DEVICE_ID);
  u32 base0 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_0);
  u32 base1 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_1);
  u32 base2 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_2);
  u32 base3 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_3);
  u32 base4 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_4);
  u32 base5 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_5);


  WinDbgPrint("Base Addresses: %08X %08X %08X %08X %08X %08X\n",
	      base0, base1, base2, base3, base4, base5);

  WinDbgPrint("Masks: %08X %08X %08X %08X %08X %08X\n",
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_0),
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_1),
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_2),
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_3),
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_4),
	      get_base_register_size(bus, slot, func, PCI_BASE_ADDRESS_5));
}

void DumpConfigSpace(u8 bus, u8 slot, u8 func) {

  u8 i, j;

  for(i=0; i<0x80; i+=0x10) {
    WinDbgPrint("0x%02X ", i);
    for(j=i; j<i+0x10; j++) {
      u8 b = read_pci_config_byte(bus, slot, func, j);
      WinDbgPrint("%02X ", b);
    };
    WinDbgPrint("\n");
  }
};

void DumpRuns(struct PmemMemoryInfo *info) {
  int i;
  for(i=0; i<info->NumberOfRuns.QuadPart; i++) {
    WinDbgPrint("0x%llx 0x%llx 0x%llx\n", info->Run[i].BaseAddress.QuadPart,
		info->Run[i].BaseAddress.QuadPart + info->Run[i].NumberOfBytes.QuadPart,
		info->Run[i].NumberOfBytes.QuadPart);
  };
};

#endif

static NTSTATUS InsertMemoryHole(struct PmemMemoryInfo *info, int len,
				 u64 start, u64 end) {
  int i;

#if WINPMEM_PCI_DEBUG
  WinDbgPrint("Inserting memory hole at Start %llX end %llx\n", start, end);
#endif

  // Round start and end to page boundaries.
  start = start & 0xFFFFFFFFFFFFF000;
  end = end | 0xFFF;

  if (start == end){
    goto exit;
  };

  for (i=0; i<info->NumberOfRuns.QuadPart; i++) {
    PHYSICAL_MEMORY_RANGE Run = info->Run[i];
    u64 run_start = Run.BaseAddress.QuadPart;
    u64 run_end = Run.BaseAddress.QuadPart + Run.NumberOfBytes.QuadPart;

    if (run_start < start && start < run_end) {
      // Make some room for a new entry.
      RtlMoveMemory(&info->Run[i+1], &info->Run[i],
		    sizeof(Run) * (info->NumberOfRuns.LowPart - i));

      info->NumberOfRuns.QuadPart++;

      info->Run[i].NumberOfBytes.QuadPart = start - run_start - 1;
      info->Run[i+1].BaseAddress.QuadPart = start;
      info->Run[i+1].NumberOfBytes.QuadPart = run_end - start - 1;
      continue;
    };

    if (run_start < end && end < run_end) {
      info->Run[i].BaseAddress.QuadPart = end + 1;
      info->Run[i].NumberOfBytes.QuadPart = run_end - end - 1;
      goto exit;
    };
  };

 exit:

#if WINPMEM_PCI_DEBUG
  DumpRuns(info);
#endif

  return STATUS_SUCCESS;
};


static NTSTATUS DumpBaseAddressRegister32(u8 bus, u8 slot, u8 func, u8 offset,
					  struct PmemMemoryInfo *info, int len) {
  u32 mask = 0;
  u32 base = read_pci_config(bus, slot, func, offset);
  u16 command = read_pci_config_16(bus, slot, func, PCI_COMMAND);

  // Disable IO and memory bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, 0);

  write_pci_config(bus, slot, func, offset, 0xFFFFFFFF);
  mask = read_pci_config(bus, slot, func, offset) & 0xFFFFFFF0;
  write_pci_config(bus, slot, func, offset, base);

  // Reenable bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, command);

  base = base & 0xFFFFFFF0;
  return InsertMemoryHole(info, len, base, ~mask + base);
};


static NTSTATUS DumpBaseAddressRegister64(u8 bus, u8 slot, u8 func, u8 offset,
					  struct PmemMemoryInfo *info, int len) {
  u64 base = read_pci_config(bus, slot, func, offset);
  u32 base_high = read_pci_config(bus, slot, func, offset + sizeof(u32));
  u32 mask = 0;
  u32 mask_high = 0;
  u64 end = 0;
  u16 command = read_pci_config_16(bus, slot, func, PCI_COMMAND);

  // Disable IO and memory bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, 0);

  // Check the lower word first.
  write_pci_config(bus, slot, func, offset, 0xFFFFFFFF);
  mask = read_pci_config(bus, slot, func, offset) & 0xFFFFFFF0;
  write_pci_config(bus, slot, func, offset, (u32)base);

  // Check the upper 32 bit word.
  write_pci_config(bus, slot, func, offset + sizeof(u32), 0xFFFFFFFF);
  mask_high = read_pci_config(bus, slot, func, offset + sizeof(u32));
  write_pci_config(bus, slot, func, offset + sizeof(u32), (u32)base_high);

  // Reenable bus access.
  write_pci_config_16(bus, slot, func, PCI_COMMAND, command);

  base = ((base & 0xFFFFFFF0) | ((u64)base_high) << 32);
  end = ~(mask | ((u64)mask_high) << 32) + base;

  return InsertMemoryHole(info, len, base, end);
};


// Advances the offset depending on the size of the base address register.
static NTSTATUS DumpBaseAddressRegister(u8 bus, u8 slot, u8 func, u8 *offset,
					struct PmemMemoryInfo *info, int len) {
  u64 base = read_pci_config(bus, slot, func, *offset) & 0xFFFFFFFF;

  if (base == 0) {
    *offset += sizeof(u32);
    return STATUS_SUCCESS;
  };

  // We skip IO space registers since they are not interesting for memory
  // acquisition.
  if ((base & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO) {
    *offset += sizeof(u32);

    // 64 bit base address register.
  } else if ((base & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
      PCI_BASE_ADDRESS_MEM_TYPE_64) {

    DumpBaseAddressRegister64(bus, slot, func, *offset, info, len);
    *offset += sizeof(u64);

    // 32 bit memspace or io space base address register.
  } else if ((base & PCI_BASE_ADDRESS_SPACE) ==
             PCI_BASE_ADDRESS_SPACE_MEMORY) {
    DumpBaseAddressRegister32(bus, slot, func, *offset, info, len);
    *offset += sizeof(u32);

  } else {
    // Something else - Just advance the offset one word forward.
    *offset += sizeof(u32);
  };

  return STATUS_SUCCESS;
};



static NTSTATUS DumpStandardHeader(u8 bus, u8 slot, u8 func,
				   struct PmemMemoryInfo *info, int len) {
  u8 offset;

  // For standard devices we just go over all their base address registers.
  for(offset = PCI_BASE_ADDRESS_0; offset <= PCI_BASE_ADDRESS_5;) {
    DumpBaseAddressRegister(bus, slot, func, &offset, info, len);
  };

  return STATUS_SUCCESS;
};


static NTSTATUS DumpPCIBridge(u8 bus, u8 slot, u8 func,
			      struct PmemMemoryInfo *info, int len) {
  u8 offset;
  u64 base;
  u64 limit;

  // Support direct Bridge BARs.
  for(offset = PCI_BASE_ADDRESS_0; offset <= PCI_BASE_ADDRESS_1;) {
    DumpBaseAddressRegister(bus, slot, func, &offset, info, len);
  };

  // I/O base and limit registers are not interesting for memory acquisition.

  // Memory base and limit registers.
  base = read_pci_config_16(bus, slot, func, PCI_MEMORY_BASE);
  if (base != 0) {
    base = (base & 0xFFF0) << 20;
    limit = read_pci_config_16(bus, slot, func, PCI_MEMORY_LIMIT);

    limit = (limit & 0xFFF0) << 20 | 0xFFFFFF;
    if (limit > base) {
      InsertMemoryHole(info, len, base, limit);
    };
  };

  // Prefetcheable Memory base and limit registers.
  base = read_pci_config_16(bus, slot, func, PCI_PREF_MEMORY_BASE);
  if (base != 0) {
    // Determine if the base register is 32 or 64 bit.
    if ((base & 0xF) == 0) {
      base = (base & 0xFFF0) << 20;
    } else {
      base = ((base & 0xFFF0) << 20) |
	((u64)read_pci_config(bus, slot, func, PCI_PREF_BASE_UPPER32) << 32);
    };

    limit = read_pci_config_16(bus, slot, func, PCI_PREF_MEMORY_LIMIT);

    // Determine if the limit register is 32 or 64 bit.
    if ((limit & 0xF) == 0) {
      limit = (limit & 0xFFF0) << 20 | 0xFFFFFF;
    } else {
      limit = ((limit & 0xFFF0) << 20) | 0xFFFFFF |
	((u64)read_pci_config(bus, slot, func, PCI_PREF_LIMIT_UPPER32) << 32);
    };

    if (limit > base) {
      InsertMemoryHole(info, len, base, limit);
    };
  };

  return STATUS_SUCCESS;
};


/*
  Uses direct PCI probing to add accessible physical memory ranges.
*/
NTSTATUS PCI_AddMemoryRanges(struct PmemMemoryInfo *info, int len) {
  int required_length = (sizeof(struct PmemMemoryInfo) +
			 sizeof(PHYSICAL_MEMORY_RANGE));
  unsigned int bus, slot, func;

  if (len < required_length) {
    return STATUS_INFO_LENGTH_MISMATCH;
  };

  // Initialize the physical memory range.
  info->NumberOfRuns.QuadPart = 1;
  info->Run[0].BaseAddress.QuadPart = 0;
  info->Run[0].NumberOfBytes.QuadPart = -1;

  for (bus = 0; bus < 256; bus++) {
    for (slot = 0; slot < 32; slot++) {
      for (func = 0; func < 8; func++) {
	u8 type;

	u16 vendor_id = read_pci_config_16((u8)bus, (u8)slot, (u8)func,
					   PCI_VENDOR_ID);

	// Device not present.
	if (vendor_id == 0xffff)
	  continue;

	type = read_pci_config_byte((u8)bus, (u8)slot, (u8)func,
				    PCI_HEADER_TYPE);

        // Standard header.
	if ((type & 0x1f) == 0) {

#if WINPMEM_PCI_DEBUG
          WinDbgPrint("PCI Type %X\n", type);
          dump_interesting_fields((u8)bus, (u8)slot, (u8)func);
          dump_bar((u8)bus, (u8)slot, (u8)func);
          DumpConfigSpace((u8)bus, (u8)slot, (u8)func);
#endif
	  DumpStandardHeader((u8)bus, (u8)slot, (u8)func, info, len);

	  // PCI-PCI bridge.
	} else if ((type & 0x1f) == 1) {

#if WINPMEM_PCI_DEBUG
          WinDbgPrint("PCI Type %X\n", type);
          dump_interesting_fields((u8)bus, (u8)slot, (u8)func);
          DumpConfigSpace((u8)bus, (u8)slot, (u8)func);
#endif

	  DumpPCIBridge((u8)bus, (u8)slot, (u8)func, info, len);

	} else {
	  WinDbgPrint("Unknown header PCI at 0000:%02x:%02x.%d type %d\n",
		      bus, slot, func, type);
	};

	// This is not a multi function device.
	if (func == 0 && (type & 0x80) == 0) {
	  break;
	};
      }
    }
  }

  return STATUS_SUCCESS;
};
