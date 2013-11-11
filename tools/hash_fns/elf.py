import os, sys, struct, hashlib

import vmem_getbytes

reader     = vmem_getbytes.get_bytes()

def open_file(filename):
    return open(filename,"r").read()

class symbol:

    def __init__(self, name, off, val, size, digest, althash, alt2):
        self.name    = name
        self.offset  = off
        self.val     = val
        self.size    = size
        self.digest  = digest
        self.althash = althash 
        self.alt2    = alt2

nops = ["", "\x90", "\x66\x90", "\x0f\x1f\x00", "\x0f\x1f\x40\x00", "\x0f\x1f\x44\x00\x00", "\x66\x0f\x1f\x44\x00\x00", "\x0f\x1f\x80\x00\x00\x00\x00", "\x0f\x1f\x84\x00\x00\x00\x00\x00"]
nops2 = ["", "\x90", "\x89\xf6", "\x8d\x76\x00", "\x8d\x74\x26\x00", "\x90\x8d\x74\x26\x00", "\x8d\xb6\x00\x00\x00\x00", "\x8d\xb4\x26\x00\x00\x00\x00", "\x90\x8d\xb4\x26\x00\x00\x00\x00"]

class Elf32:
    
    loadoffset = 0xc0000000

    fmt = {
                "header" : "<16sHHIIIIIHHHHHH",
                "shdr"   : "<IIIIIIIIII",
                "sym"    : "<IIIBBH"
                }
    
    vmlinux = {
                "loadoff" : loadoffset + 0x1000
              } 

# constructor takes filename

class Elf:
          
    Elf_fmt = Elf32.fmt 
    
    Elf_vmlinux = Elf32.vmlinux  
    
    loadoffset = Elf32.loadoffset     
    
    # all the symbols of the elf file, used to compare with system.map
    elf_symbols = []    
    
    elf_symtab  = 0
    elf_strtab  = 0
    elf_text    = 0
    
    elf_header  = 0
    
    def __init__(self, filename):
        
        self.filedata = open_file(filename)                        
        
        self.elf_header  = ElfHeader(self.filedata) 
        
        self.elf_shdrs   = ElfSectionHeaders(self.filedata, self.elf_header)
        self.elf_symbols = ElfSymbols(self.filedata)  
                   
        self.parse_elf()       
        
    def parse_elf(self):
        
        self.elf_shdrs.fill_shdrs() # self.elf_header.e_shoff

        self.elf_symtab = self.elf_shdrs.get_shdr(".symtab")
        self.elf_strtab = self.elf_shdrs.get_shdr(".strtab")
        self.elf_text   = self.elf_shdrs.get_shdr(".text")   
        self.alt_instrs = self.elf_shdrs.get_shdr(".altinstructions")
        self.alt_reps   = self.elf_shdrs.get_shdr(".altinstr_replacement")

        
        if self.elf_symtab and self.elf_strtab and self.elf_text:

            self.elf_symbols.fill_alt_table(self.alt_instrs, self.alt_reps, self.elf_text)
            self.elf_symbols.fill_syms(self.elf_symtab, self.elf_strtab, self.elf_header.e_entry, self.elf_text)              


class ElfHeader:
        
    EI_CLASS        = 4     
    EI_DATA         = 5     
    EI_VERSION      = 6
       
    ELFCLASS32      = 1
    ELFCLASS64      = 2
    ELFDATA2LSB     = 1
    
    def __init__(self, f):
        self.set_header(f)
    
    def __str__(self):
        print "Elf Header\n"
        
        for name, attr in [
                           ("Type", "e_type"),
                           ("Machine", "e_machine"),
                           ("Version", "e_version"),
                           ("Entry point address", "e_entry"),
                           ("Start of program headers", "e_phoff"),
                           ("Start of section headers", "e_shoff"),
                           ("Flags", "e_flags"),
                           ("Size of this header", "e_ehsize"),
                           ("Size of program headers", "e_phentsize"),
                           ("Number of program headers", "e_phnum"),
                           ("Size of section headers", "e_shentsize"),
                           ("Number of section headers", "e_shnum"),
                           ("Section header string table index", "e_shstrndx"),
                           ]:
                f.write("  %-35s%s\n" % ("%s:" % name, getattr(self.ai, attr)))
        
    def set_members(self, string):
        (self.e_ident, self.e_type, self.e_machine, self.e_version,
         self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = string    
    
    def set_header(self, f): 
        
         self.set_members(reader.get_bytes(f,0, Elf.Elf_fmt["header"]))
         
        
class alt_ent:

    def __init__(self, ipaddr, ilen, repbytes, replen):

        self.addr   = ipaddr
        self.ilen   = ilen
        self.rbytes = repbytes
        self.rlen   = replen

class ElfSymbols(Elf):
    
    STT_FUNC  = 2
    
    def __init__(self, f):
        self.filedata = f
        self.symbols  = []

    def set_sym(self, off):
        (self.st_name, self.st_value, self.st_size, 
         self.st_info, self.st_other, self.st_shndx) = reader.get_bytes(self.filedata, off, Elf.Elf_fmt["sym"])

    def fill_alt_table(self, instrs, reps, text):

        return

        altfmt = "IIBBBB"

        offset  = instrs["offset"]
        sh_size = instrs["sh_size"]

        numalts = sh_size / 0xc
    
        self.alts = {}

        for i in xrange(0, numalts):

            (instraddr, repaddr, u, ilen, rlen, pad) = reader.get_bytes(self.filedata, offset + (i * 0xc), altfmt)

            #start = instraddr - instrs["addr"] + text["offset"]

            #iinstrs = self.filedata[start : start + ilen]

            start = repaddr - reps["addr"] + reps["offset"]

            repis  = self.filedata[start : start + rlen]
                 
            self.alts[instraddr] = alt_ent(instraddr, ilen, repis, rlen)


    def fill_syms(self, symtab, strtab, e_entry, text):
        
        self.offset = 0
        
        r = symtab["sh_size"] / symtab["sh_ent"]       
        
        #print "looking at %d symbols" % r
        
        for i in range(r):
            
            self.offset = symtab["offset"] + (i * symtab["sh_ent"])
            
            self.set_sym(self.offset)
            
            self.sym_type = self.st_info & 0xf
         
            ''' 
            if self.st_value == 0xc035fa20:
                print "looking at debug",
                print " %d | %d | %d | %d" % (self.st_name, self.st_size, self.sym_type, self.st_shndx)
            ''' 

            if (self.st_value != 0 
                and self.st_name != 0 
                and self.st_size != 0
                and self.sym_type == self.STT_FUNC
                and self.st_shndx == text["index"]
                ):
               
                ''' 
                if self.st_value == 0xc035fa20:
                    print "found debug"
                '''

                self.name = reader.get_bytes(self.filedata, strtab["offset"] + self.st_name, "str")
                
                self.r_off = text["offset"] + self.st_value - e_entry 

                self.r_off -= self.Elf_vmlinux["loadoff"]
  
                self.code = self.filedata[self.r_off:self.r_off + self.st_size]
            
                self.digest   = hashlib.md5(self.code).hexdigest()               
                
                #alts      = self.alts #self.calc_alt(self.filedata, self.st_value)
    
                '''
                altdigest = 0
            
                
                newcode = self.code
                newcode2 = self.code
                # have to go through all each time since its < <
                for alt in alts:
                   
                    alt = alts[alt]
 
                    istart  = alt.addr
                    rbytes  = alt.rbytes
                    rlen = len(rbytes)
                    ilen = alt.ilen                

                    blen = len(self.code)

                    # if reps are inside this function
                    if self.st_value <= istart < self.st_value + self.st_size:
                        
                        offset = istart - self.st_value    

                        skip   = rlen
                        padlen = ilen - rlen

                        pad = nops[padlen]
                        newcode = newcode[:offset] + rbytes + pad + newcode[offset+skip+len(pad):]

                        pad2 = nops2[padlen]
                        newcode2 = newcode2[:offset] + rbytes + pad2 + newcode2[offset+skip+len(pad2):]

                        if len(newcode) != blen:
                            print "%x offset: %d i: %d r: %d pad: %d %d" % (istart, offset, ilen, rlen, ilen-rlen, len(pad))
                            print "%x | %x | %d" % (istart, self.st_value, offset)
                            print "BAD CHANGED CODE LEN %d %d" % (blen, len(newcode))
                            sys.exit(1)
                        
                        altdigest = hashlib.md5(newcode).hexdigest() 
                        alt2      = hashlib.md5(newcode2).hexdigest()
                     
                        if self.name == "save_i387":
                            print "changed: %x offset: %d i: %d r: %d pad: %d" % (istart, offset, ilen, rlen, ilen-rlen)
 
  
                
                if self.name == "save_i387":
                    #print "%x offset: %d i: %d r: %d pad: %d" % (istart, offset, ilen, rlen, ilen-rlen)
                    #for r in rbytes:
                    #    print "%x " % ord(r),
                    #print ""
                    #for i in xrange(-5, 5):
                    #    print "%d | %x " % (offset+pad+i, ord(self.code[offset+pad+i])),
                    #print ""
                    f = open("code.txt", "wb")
                    f.write(self.code)
                    f.close()
                    f = open("newcode.txt", "wb")
                    f.write(newcode)
                    f.close()
                    f = open("newcode2.txt", "wb")
                    f.write(newcode2)
                    f.close()
                    # sys.exit(1)
                #else:
                #    continue
                '''
            
                altdigest = 0
                alt2 = 0

                self.symbols.append(symbol(self.name,   
                                           self.r_off,       
                                           self.st_value,   
                                           self.st_size,    
                                           self.digest,
                                           altdigest, alt2))    
                            
        #sys.exit(1)
            
    def get_sym(self, sym):
    
        if sym in self.symbols:
            ret = self.symbols[sym]
        else:
            ret = ""

        return ret
    
class ElfSectionHeaders():
    
    # offset : offset into elf file of schdr
    # size   : size of each entry
    # count  : number of section hdrs
    def __init__(self, f, hdr):
        self.offset   = hdr.e_shoff
        self.size     = hdr.e_shentsize
        self.count    = hdr.e_shnum
        self.stridx   = hdr.e_shstrndx        
        self.sections = {}
        self.filedata = f # hack++
        
        #ensure size of each section header is the size of the fmt string
        assert self.size == struct.calcsize(Elf.Elf_fmt["shdr"])
    
    def set_shdr(self,off):
        
        (self.sh_name, self.sh_type, self.sh_flags, self.sh_addr,self.sh_offset,
         self.sh_size, self.sh_link, self.sh_info,
         self.sh_addralign, self.sh_entsize) = reader.get_bytes(self.filedata, off, Elf.Elf_fmt["shdr"])    
    
    # offset: offset into elf file of start of section headers
    # can be retrieved from elf header
    def fill_shdrs(self):
        
        # once this block works don't touch it
        self.names_off  = self.offset + ( self.stridx * self.size ) 
        self.names_shdr = self.set_shdr(self.names_off)
        self.names_off  = self.sh_offset 
                
        for i in range(self.count):
            
            off = self.offset + (self.size * i)
            
            # this sets all the self.* members relating to the *current* shdr
            # must be called before operating on any self.sh_* members for the current shdr
            self.set_shdr(off)
            
            cur_name = self.names_off + self.sh_name     
            str_name = reader.get_bytes(self.filedata,cur_name,"str")     
            
            self.sections[str_name] = {
                                       "addr"    : self.sh_addr,
                                       "offset"  : self.sh_offset,
                                       "sh_size" : self.sh_size,
                                       "sh_ent"  : self.sh_entsize,
                                       "index"     : i
                                      }      
        
    def get_shdr(self, shdr):
        
        if shdr in self.sections:
            return self.sections[shdr]
        else:
            print "returning null\n"
            # kill code here
            return ""
        


def main():
    filename = sys.argv[1]
    elfObj   = Elf(filename)    
    if(elfObj == ""): # how to check for false/null?
        error("Invalid Elf File")
        
        
if __name__ == "__main__":
        main()
        
    





