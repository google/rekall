---
layout: plugin
title: version_modules
abstract: |
  Try to determine the versions for all kernel drivers.

epydoc: rekall.plugins.windows.modules.ModVersions-class.html
args:
  name_regex: 'Filter module names by this regex.'
  address_space: 'The address space to use.'

---


Each time a windows binary is built using the Microsoft Visual Studio compiler
suite a new unique GUID is generated for this file. The GUID is used to link the
executable and the pdb file (which contains debugging symbols).

The GUID is embedded in the executable in an `RSDS` record (i.e. the record has
a signature starting with the letters `RSDS`). Rekall can scan for this
signature in order to identify the executable version.

This plugin scans for the version string for each loaded kernel module. Use the
[version_scan](VersionScan.html) module to search for RSDS signatures in
physical memory.

### Sample output

```
win7_trial_64bit.dmp.E01 23:48:26> version_modules
  Offset (V)   Name                 GUID/Version                     PDB
-------------- -------------------- -------------------------------- ------------------------------
0xf800027f4b0c ntoskrnl.exe         C07170995AA8441B952E3B9AE3F3754B2 ntkrnlmp.pdb
0xf8000262deb4 hal.dll              0C72B43B8AC64E22AB88B564E69330372 hal.pdb
0xf88002d34af4 wanarp.sys           7BA2309F029F4DE7878AED80636C2D132 wanarp.pdb
0xf8800183eed4 TDI.SYS              C519554437F04B63BC39FF4E69578DC42 tdi.pdb
0xf88000d95b24 volmgrx.sys          C047BA32ABCB4A948CBB8930F352B1032 volmgrx.pdb
0xf88003de7c60 dump_dumpfve.sys     A2CC4DFB86424750871BCB8E1E841E3C1 dumpfve.pdb
0xf880019d4e00 watchdog.sys         79ACBD31D1BD428A8311AD9D5DCDEAA61 watchdog.pdb
0xf8800111004c cng.sys              F0AA00E320D4468A9D3F7078E2AE2BF52 cng.pdb
0xf88002c2e648 csc.sys              56B7C3B9040B47D9821E6A57E6A5AE4A1 csc.pdb
0xf88000c02f48 CI.dll               5F1BDC2205AC402CB0F09FC7CF17A3701 ci.pdb
0xf88003c3f2dc USBD.SYS             BE6200B21204452DADDF85CED51A5BDE1 usbd.pdb
0xf88002d0a1fc netbios.sys          084EB51DBDE844CF9EAD3B5FDFABDC721 netbios.pdb
0xf88000cc80a0 mcupdate.dll         8C7A27566CD54FB9A00AF26B5BF941651 mcupdate_GenuineIntel.pdb
0xf8800145c920 ndis.sys             40D6C85AC9F74887A652601839A1F56D2 ndis.pdb
0xf880019eb04c rdpencdd.sys         C299649119AC4CC888F37C32A216781A1 RDPENCDD.pdb
0xf88003814d08 srv.sys              20C4A475BE954C10997EAD2C623E40C32 srv.pdb
0xf88003a52c10 raspptp.sys          C9106AFB80474EFCAF9384DA26CC35622 raspptp.pdb
0xf880019b42ec VIDEOPRT.SYS         1B0FC2CC31FE41CEBEAC4ABB7375EA481 videoprt.pdb
0xf88000fda340 PCIIDEX.SYS          2C4F146DA2774ACEA1D5499284DDDB271 pciidex.pdb
0xf88003c2962c HIDCLASS.SYS         1815DD7E268B4BB9BCD5226204CFEC9C1 hidclass.pdb
0xf88000fd105c intelide.sys         B72598DF61A84806B7AC593BA128300C1 intelide.pdb
0xf88003a37320 raspppoe.sys         39B224364B9042649CA0CDB8270762931 raspppoe.pdb
0xf88000e040ec atapi.sys            4E82D8C0AB5A41799B979539D280167D1 atapi.pdb
0xf88002cba464 netbt.sys            840D3E3C828C4D60A905DC82D8CBF8FA2 netbt.pdb
0xf880011f647c kbdclass.sys         D5F7E088FAF44B60A3774197A9ADEEC01 kbdclass.pdb
0xf88000e361f0 amdxata.sys          8D1A5FFBAEEA4D388F8B7B3B9378C3671 amdxata.pdb
0xf880031abb04 srvnet.sys           608D364BC5524794BD70C89773BD51EF2 srvnet.pdb
0xf880028fa614 bowser.sys           26FAC99A52F8439E9A5B8B4B37F90D5B1 bowser.pdb
0xf88002ddb6f4 dfsc.sys             827F5D478C94478299C7FEC7FEE4DAFA1 dfsc.pdb
0xf880011bf9dc fvevol.sys           2FBEA7856251499B87C65A29FC51E6191 fvevol.pdb
0xf80000bc13b0 kdcom.dll            ACC6A823A2844D22B68CD5D48D42381F2 kdcom.pdb
0xf88000fbe5a4 volmgr.sys           39E92F60716140C38C723CDF21B956CD2 volmgr.pdb
0xf88000f5c108 msisadrv.sys         09A612E6691847ED98E4F36F3CC9EE641 msisadrv.pdb
0xf8800183127c tdx.sys              FB912A34EB1A44EC9F65E250879944B52 tdx.pdb
0xf8800119f10c rdyboost.sys         20E6E50C6F9B42589E18D96AD84608DB1 rdyboost.pdb
```