---
abstract: Scan certificates in process Vads.
args: {dump_dir: 'Path suitable for dumping files. (Default: Use current directory)',
  eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", phys_eprocess: 'Physical addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: CertVadScan
epydoc: rekall.plugins.windows.dumpcerts.CertVadScan-class.html
layout: plugin
module: rekall.plugins.windows.dumpcerts
title: cert_vad_scan
---

This plugin is similar to the [certscan](CertScan.html) plugin. It attempts to detect
DER encoded X509 certificates or RSA private keys in memory. This plugin scans
the process memory of selected processes only. The usualy process selection
arguments are supported in order to restrict the search to some processes only.

Optionally, if a dump directory is provided the DER encoded certificates are
also dumped to files in the specified directory.


### Sample Output

In the example below we scan the address space of the winpmem acquistion tool to
find certificates used to sign the driver and binary.

```
win8.1.raw 22:07:16> cert_vad_scan proc_regex="winpmem"
-------------------> cert_vad_scan(proc_regex="winpmem")
Pid   Command       Address     Type  Length Description
----- ---------- -------------- ----- ------ -----------
2628  winpmem_1.5.2. 0x00000003c179 X509  1010  /C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2
2628  winpmem_1.5.2. 0x00000003c56b X509  1191  /C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4
2628  winpmem_1.5.2. 0x00000003ca12 X509  1343  /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
2628  winpmem_1.5.2. 0x00000003cf51 X509  1690  /C=CH/ST=Switzerland/L=Horgen/O=Michael Cohen/CN=Michael Cohen
2628  winpmem_1.5.2. 0x00000003d285 X509  443   -
2628  winpmem_1.5.2. 0x00000003d5eb X509  1734  /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance Code Signing CA-1
2628  winpmem_1.5.2. 0x00000003d87c X509  442   -
2628  winpmem_1.5.2. 0x000000bd2260 X509  704   /O=VeriSign Trust Network/OU=VeriSign, Inc./OU=VeriSign Time Stamping Service Root/OU=NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.
2628  winpmem_1.5.2. 0x000000bd2720 X509  462   /CN=Root Agency
2628  winpmem_1.5.2. 0x000000c153b0 X509  1491  /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=MOPR/CN=Microsoft Update
```














