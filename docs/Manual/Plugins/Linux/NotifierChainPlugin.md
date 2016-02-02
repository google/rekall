---
abstract: Outputs and verifies kernel notifier chains.
args: {}
class_name: NotifierChainPlugin
epydoc: rekall.plugins.linux.notifier_chains.NotifierChainPlugin-class.html
layout: plugin
module: rekall.plugins.linux.notifier_chains
title: notifier_chains
---

The Linux kernel can notify modules on certain events. This is done by subscribing to a notifier chain.
A notifier chain is an ordered list of functions the kernel will call when an event is triggered.

Rekall analyzes the following notifier chains and shows whether there's any callback function registered:
 - The `keyboard_notifier_list`, which is used to notify on keyboard events and some keyloggers use. 
 - `vt_notifier_list`, which is used to notify when there's events on a virtual terminal and could be used to assist in monitoring ttys.

Normally, no callbacks will be registered in any of these notifier chains and Rekall will produce no output.

### Sample output

```
$ PYTHONPATH=. python rekall/rekal.py -f Linux-3.2.0-4-686-pae.E01 --profile_path ../my-profiles/ https://raw.githubusercontent.com/google/rekall-profiles/master/ - notifier_chains
      Chain symbol        Index Priority  Address          Module                         Symbol                 
------------------------- ----- -------- ---------- -------------------- ----------------------------------------
```
