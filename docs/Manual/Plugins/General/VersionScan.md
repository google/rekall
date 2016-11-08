---
abstract: Scan the physical address space for RSDS versions.
args: {name_regex: 'Filter module names by this regex. (type: RegEx)



    * Default: .', scan_filename: 'Optional file to scan. If not specified we scan
    the physical address space. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: VersionScan
epydoc: rekall.plugins.windows.modules.VersionScan-class.html
layout: plugin
module: rekall.plugins.windows.modules
title: version_scan
---

When the Microsoft Compilers create a binary (Executable or DLL) they leave a
unique GUID in the PE header, so that the corresponding PDB file can be located
for this binary.

The GUID is encoded using a known signature and therefore we can scan for all
GUIDs which might appear in the memory image. This is useful to locate the exact
version of binaries running in the memory image. Often malware authors forget to
disable PDB file generation in Visual Studio and the GUID remains in the
malware. In that case scanning for a known malicious GUID can be a strong
signature.

In the below example we scan the memory image for the exact version of the
windows kernel. Note how hits can be restricted by using a regular expression.

```text
[1] win7.elf 00:01:51> version_scan name_regex="krnl"
  Offset (P)             GUID/Version                         PDB
-------------- --------------------------------- ------------------------------
0x0000027bb5fc F8E2A8B5C9B74BF4A6E4A48F180099942 ntkrnlmp.pdb
```
