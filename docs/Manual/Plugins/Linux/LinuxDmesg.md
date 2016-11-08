---
abstract: Gathers dmesg buffer.
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LinuxDmesg
epydoc: rekall.plugins.linux.dmesg.LinuxDmesg-class.html
layout: plugin
module: rekall.plugins.linux.dmesg
title: dmesg
---

### Sample output

```
[1] Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 16:07:44> dmesg
---------------------------------------------------------------------------> dmesg()
Timestamp Facility Level                                     Message                                     
--------- -------- ----- --------------------------------------------------------------------------------
     0.00 0        LOG_INFO Initializing cgroup subsys cpuset                                               
     0.00 0        LOG_INFO Initializing cgroup subsys cpu                                                  
     0.00 0        LOG_INFO Initializing cgroup subsys cpuacct                                              
     0.00 0        LOG_INFO Linux version 3.11.0-12-generic (buildd@allspice) (gcc version 4.8.1 (Ubuntu/Linaro 4.8.1-10ubuntu7) ) #19-Ubuntu SMP Wed Oct 9 16:20:46 UTC 2013 (Ubuntu 3.11.0-12.19-generic 3.11.3)
     0.00 0        LOG_INFO Command line: BOOT_IMAGE=/vmlinuz-3.11.0-12-generic root=/dev/mapper/ubuntu--vmware--vg-root ro
     0.00 0        LOG_INFO KERNEL supported cpus:                                                          
     0.00 0        LOG_INFO   Intel GenuineIntel                                                            
     0.00 0        LOG_INFO   AMD AuthenticAMD                                                              
     0.00 0        LOG_INFO   Centaur CentaurHauls                                                          
     0.00 0        LOG_INFO Disabled fast string operations                                                 
     0.00 0        LOG_INFO e820: BIOS-provided physical RAM map:                                           
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x0000000000000000-0x000000000009ebff] usable                   
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x000000000009ec00-0x000000000009ffff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000000ca000-0x00000000000cbfff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000000dc000-0x00000000000fffff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x0000000000100000-0x000000003fedffff] usable                   
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x000000003fee0000-0x000000003fefefff] ACPI data                
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x000000003feff000-0x000000003fefffff] ACPI NVS                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x000000003ff00000-0x000000003fffffff] usable                   
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000f0000000-0x00000000f7ffffff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000fec00000-0x00000000fec0ffff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000fee00000-0x00000000fee00fff] reserved                 
     0.00 0        LOG_CRIT BIOS-e820: [mem 0x00000000fffe0000-0x00000000ffffffff] reserved                 
     0.00 0        LOG_INFO NX (Execute Disable) protection: active                                         
     0.00 0        LOG_INFO SMBIOS 2.4 present.                                                             
     0.00 0        LOG_INFO DMI: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/31/2013
     0.00 0        LOG_INFO Hypervisor detected: VMware                                                     
     0.00 0        LOG_CRIT e820: update [mem 0x00000000-0x00000fff] usable ==> reserved                    
     0.00 0        LOG_CRIT e820: remove [mem 0x000a0000-0x000fffff] usable                                 
     0.00 0        LOG_INFO                                                                                 
```
