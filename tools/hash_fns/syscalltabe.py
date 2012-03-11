import sys, os, struct

import elf, vmem_getbytes

reader     = vmem_getbytes.get_bytes()

def hash_syms(elf):
    
    elf_syms = elf.elf_symbols.symbols    

    taddr    = 2528864
    numbytes = 400 * 4

    table = elf.elf_symbols.filedata[taddr : taddr + numbytes]

    addrs = [x.val for x in elf_syms]

    kaddrs = []

    for idx in xrange(0, numbytes, 4):

        addr = struct.unpack("I", table[idx:idx+4])[0]

        if not addr in addrs:
            break

        print "%x" % addr
    

def main():
    
    vmlinux = sys.argv[1]
    
    elfObj = elf.Elf(vmlinux)
    hash_syms(elfObj)   
 
if __name__ == "__main__":
    main()
        
