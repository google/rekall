#!/usr/bin/env python
"""Uses ko_patcher to fix the __vermagic of a kernel module."""
import sys

from ko_patcher import KernelObjectPatcher

def update_symbol_versions(module):
  """Updates all checksums in a modules "__versions" section."""
  patcher = KernelObjectPatcher()
  sections = patcher.GetSectionOffsets(module)
  versions = patcher.GetImportedVersions(module, sections)
  available_versions = patcher.GetKnownImports(versions)
  new_versions = ""
  for function in versions.keys():
    if versions[function] == available_versions[function]:
      print "[+] %s is compatible, no need to update" %  function.replace(
          "\x00", "")
    else:
      print "[-] %s not compatible, updating..." % function.replace("\x00", "")
    new_versions += available_versions[function] + function
  return patcher.ReplaceSection(module, sections["__versions"][0], new_versions)

if __name__ == "__main__":
  if len(sys.argv) != 3:
    print "usage: %s [KERNEL MODULE] [OUTPUT FILE]" % sys.argv[0]
    sys.exit(-1)
  else:
    print "Scanning __versions in module %s" % sys.argv[1]
    try:
      fd = open(sys.argv[1], "rb")
    except (OSError, IOError) as e:
      print "Failed to open %s: %s" % (sys.argv[1], e)
      sys.exit(-1)
    module = fd.read()
    fd.close()
    patched_module = update_symbol_versions(module)
    try:
      out_fd = open(sys.argv[2], "w")
    except (OSError, IOError) as e:
      print "Failed to open %s: %s" % (sys.argv[1], e)
      sys.exit(-1)
    out_fd.write(patched_module)
    out_fd.close()
    fd.close()
    print "Successfully updated __versions in module %s" % sys.argv[2]
