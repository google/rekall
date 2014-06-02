---
layout: plugin
title: certscan
abstract: |
  Dump RSA private and public SSL keys from the physical address space.

epydoc: rekall.plugins.windows.dumpcerts.CertScan-class.html
args:
  dump_dir: 'Path suitable for dumping files. (Optional)'

---

This plugin is similar to the [cert_vad_scan](CertVadScan.html) plugin. It
attempts to detect DER encoded X509 certificates or RSA private keys in physical
memory.

Optionally, if a dump directory is provided the DER encoded certificates are
also dumped to files in the specified directory.


### Sample Output

```
win8.1.raw 22:07:35> certscan
-------------------> certscan()
   Address     Type       Length     Description
-------------- ---------- ---------- -----------
0x000000030c95 X509       1287       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows
0x00000003119c X509       1499       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Production PCA 2011
0x000000031b94 X509       1653       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010
0x000000032209 X509       1246       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=MOPR/OU=nCipher DSE ESN:F528-3777-8A76/CN=Microsoft Time-Stamp Service
0x00000017114e X509       1499       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Production PCA 2011
0x000000171b46 X509       1653       /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010
```