---
layout: plugin
title: moddump
abstract: |
  Dumps loaded kernel modules.

epydoc: rekall.plugins.linux.lsmod.Moddump-class.html
args:
  dump_dir: 'Dump directory.'
  regexp: 'Regexp on the module name.'
  dtb: 'The DTB physical address.'

---

The list of loaded modules is obtained by running the `lsmod` plugin.

### Sample output

```
$ PYTHONPATH=. python rekall/rekal.py -f Linux-3.2.0-4-686-pae.E01 --profile_path ../my-profiles/ https://raw.githubusercontent.com/google/rekall-profiles/master/ - moddump --regex ext4 --dump_dir .
Wrote 306996 bytes to ext4.0xf836a000.lkm
```
