---
layout: plugin
title: svcscan
abstract: |
  Scan for Windows services

epydoc: rekall.plugins.windows.malware.svcscan.SvcScan-class.html
args:
  scan_in_kernel_address_space: ''

---

Windows uses services for long running processes. Serivces are managed by the
"services.exe" process. The **svcscan** plugin scans the heap memory of the
"services.exe" process for **_SERVICE_RECORD** records). These records describe
the services which are loaded by the system, and even once the services are
unloaded, we might find **_SERVICE_RECORD** records.

### Notes

1. Since loading kernel code is usually done by inserting a kernel driver, and
   kernel drivers are loaded through a service, this plugin will also show
   forensically significant kernel drivers loading.

2. This plugin relies on memory scanning and so it is not all that
   reliable. Often it will not reveal services which we know are
   running. However, it might also reveal services which have been deleted.

3. A better plugin is the **services** plugin which enumerates all services from
   the registry.

### Sample output

The below example shows a kernel driver being loaded as a service.

```
Offset: 0x26f7d6a10
Order: 402
Process ID: -
Service Name: WFPLWFS
Display Name: Microsoft Windows Filtering Platform
Service Type: SERVICE_KERNEL_DRIVER
Service State: SERVICE_RUNNING
Binary Path: \Driver\WFPLWFS
```