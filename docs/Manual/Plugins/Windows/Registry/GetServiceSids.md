---
layout: plugin
title: getservicesids
abstract: |
  Get the names of services in the Registry and return Calculated SID

epydoc: rekall.plugins.windows.registry.getservicesids.GetServiceSids-class.html
args:
  hive_offsets: 'A list of hive offsets as found by hivelist. If not provided we call hivescan ourselves and list the keys on all hives.'
  hive_regex: 'A regex to filter hive names.If not provided we use all hives.'

---



The getservicesids command calculates the SIDs for services on a machine. The
service names are taken from the registry ("SYSTEM\CurrentControlSet\Services")

### Sample output

```
win8.1.raw 16:58:23> getservicesids
-------------------> getservicesids()
SID                                                                    Service Name
---------------------------------------------------------------------- ------------
S-1-5-80-3476726845-1218940557-3240126423-1396283824-3706223860        .NET CLR Data
S-1-5-80-3749761688-76038143-2425834820-4129736068-309120712           .NET CLR Networking
S-1-5-80-4151353957-356578678-4163131872-800126167-2037860865          .NET CLR Networking 4.0.0.0
S-1-5-80-603392709-3706100282-1779817366-3290147925-2109454977         .NET Data Provider for Oracle
S-1-5-80-1168016597-2140435647-491797002-352772175-817350590           .NET Data Provider for SqlServer
S-1-5-80-1135273183-3738781202-689480478-891280274-255333391           .NET Memory Cache 4.0
S-1-5-80-255220978-1106536095-1636044468-311807000-281316439           .NETFramework
S-1-5-80-799694863-4024754253-4060439485-3284853837-2852070736         1394ohci
S-1-5-80-3459415445-2224257447-3423677131-2829651752-4257665947        3ware
S-1-5-80-550892281-1246201444-2906082186-2301917840-2280485454         ACPI
S-1-5-80-2670625634-2386107419-4204951937-4094372046-2600379021        acpiex
S-1-5-80-3267050047-1503497915-401953950-2662906978-1179039408         acpipagr
```