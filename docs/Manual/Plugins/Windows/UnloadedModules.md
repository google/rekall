---
layout: plugin
title: unloaded_modules
abstract: |
  Print a list of recently unloaded modules.

  Ref:
  http://volatility-labs.blogspot.de/2013/05/movp-ii-22-unloaded-windows-kernel_22.html

epydoc: rekall.plugins.windows.modules.UnloadedModules-class.html
args:

---

For debugging purposes windows keeps a list of the last few kernel modules to
have been unloaded. Sometimes if malware inserts a kernel component, and then
removes it this will leave traces in this list.

### Sample output

The below sample shows that `win32dd` was used to acquire this sample, and that
the Honeynet project's [capture
tools](https://projects.honeynet.org/capture-hpc/browser/capture-hpc/branches/dev/capture-client/KernelDrivers/CaptureKernelDrivers)
were used.

```
130115b.w32 22:53:17> unloaded_modules
INFO:root:Detected kernel base at 0x804D7000-
Name                   Start       End     Time
-------------------- ---------- ---------- ----
Sfloppy.SYS          0xf8383000 0xf8386000 2013-01-15 22:06:06+0000
Cdaudio.SYS          0xf89c2000 0xf89c7000 2013-01-15 22:06:06+0000
processr.sys         0xf88aa000 0xf88b3000 2013-01-15 22:06:06+0000
splitter.sys         0xf8bc6000 0xf8bc8000 2013-01-15 22:06:41+0000
aec.sys              0xb1be6000 0xb1c09000 2013-01-15 22:06:41+0000
swmidi.sys           0xb1d06000 0xb1d14000 2013-01-15 22:06:41+0000
DMusic.sys           0xb1cf6000 0xb1d03000 2013-01-15 22:06:41+0000
drmkaud.sys          0xf8c9f000 0xf8ca0000 2013-01-15 22:06:41+0000
kmixer.sys           0xb1b1b000 0xb1b46000 2013-01-15 22:06:51+0000
kmixer.sys           0xb14df000 0xb150a000 2013-01-15 22:08:04+0000
kmixer.sys           0xb14df000 0xb150a000 2013-01-15 22:09:21+0000
win32dd.sys          0xb160a000 0xb1616000 2013-01-15 22:27:39+0000
fastdumpx86.sys      0xf8942000 0xf8948000 2013-01-15 22:30:55+0000
CaptureFileMonitor.sys 0xb1c3a000 0xb1c3d000 2013-01-15 22:35:48+0000
CaptureRegistryMonitor.sys 0xf8c1e000 0xf8c20000 2013-01-15 22:39:51+0000
CaptureProcessMonitor.sys 0xf8c0e000 0xf8c10000 2013-01-15 22:39:52+0000
CaptureFileMonitor.sys 0xb15ba000 0xb15bd000 2013-01-15 22:39:52+0000
```