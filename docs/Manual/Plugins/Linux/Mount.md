---
abstract: Lists the mount points.
args: {}
class_name: Mount
epydoc: rekall.plugins.linux.mount.Mount-class.html
layout: plugin
module: rekall.plugins.linux.mount
title: mount
---

### Sample output

```
[1] Linux-3.2.0-4-686-pae.E01 12:56:57> mount
--------------------------------------> mount()
                      Device                                              Path                             Type             flags
-------------------------------------------------- -------------------------------------------------- -------------- --------------------
proc                                               /proc                                              proc           rw, nodev, noexec, nosuid, relatime
devpts                                             /dev/pts                                           devpts         rw, noexec, nosuid, relatime
tmpfs                                              /run/lock                                          tmpfs          rw, nodev, noexec, nosuid, relatime
tmpfs                                              /run/shm                                           tmpfs          rw, nodev, noexec, nosuid, relatime
udev                                               /dev                                               devtmpfs       rw, relatime
tmpfs                                              /run                                               tmpfs          rw, noexec, nosuid, relatime
rpc_pipefs                                         /var/lib/nfs/rpc_pipefs                            rpc_pipefs     rw, relatime
/dev/disk/by-uuid/55bda481-150f-442e-b781-231a904cebd1 /                                                  ext4           rw, relatime
devtmpfs                                           /                                                  devtmpfs       rw, relatime
sysfs                                              /sys                                               sysfs          rw, nodev, noexec, nosuid, relatime
```
