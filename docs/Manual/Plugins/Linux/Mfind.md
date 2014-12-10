---
layout: plugin
title: mfind
abstract: |
  Finds a file by name in memory.

epydoc: rekall.plugins.linux.fs.Mfind-class.html
args:
  path: 'Path to the file.'
  device: 'Name of the device to match.'
  dtb: 'The DTB physical address.'

---

`mfind` can and will find multiple files if more than one file potentially matches the path.
You can use the `--device` parameter to filter out by device name if you want to target a specific mountpoint.

### Sample output

```
[1] Linux-3.2.0-4-686-pae.E01 12:56:58> mfind "/etc/passd"
--------------------------------------> mfind("/etc/passd")
[1] Linux-3.2.0-4-686-pae.E01 12:58:00> mfind "/etc/passwd"
--------------------------------------> mfind("/etc/passwd")
Files on device /dev/disk/by-uuid/55bda481-150f-442e-b781-231a904cebd1 mounted at /.
   Perms       uid        gid          size               mtime                    atime                    ctime             inode                                path
----------- ---------- ---------- -------------- ------------------------ ------------------------ ------------------------ ---------- ------------------------------------------------------------
-rw-r--r--           0          0            942 2013-12-03 12:21:50+0000 2014-11-28 10:59:14+0000 2013-12-03 12:21:50+0000        128 /etc/passwd
[1] Linux-3.2.0-4-686-pae.E01 12:58:05> mfind "/dev/pts/0"
--------------------------------------> mfind("/dev/pts/0")
[1] Linux-3.2.0-4-686-pae.E01 12:58:12> mfind "/dev/pts"
--------------------------------------> mfind("/dev/pts")
Files on device devpts mounted at /dev/pts.
   Perms       uid        gid          size               mtime                    atime                    ctime             inode                                path
----------- ---------- ---------- -------------- ------------------------ ------------------------ ------------------------ ---------- ------------------------------------------------------------
drwxr-xr-x           0          0              0 2014-11-28 11:40:08+0000 2014-11-28 11:40:08+0000 2014-11-28 11:40:08+0000          1 /dev/pts
Files on device udev mounted at /dev.
   Perms       uid        gid          size               mtime                    atime                    ctime             inode                                path
----------- ---------- ---------- -------------- ------------------------ ------------------------ ------------------------ ---------- ------------------------------------------------------------
drwxr-xr-x           0          0             40 2014-11-28 11:40:08+0000 2014-11-28 11:40:08+0000 2014-11-28 11:40:08+0000       1137 /dev/pts
```

