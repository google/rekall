
---
layout: plugin
title: check_ttys
abstract: |
    Checks tty devices for hooks.

    Some malware insert a hook into the ops struct of the tty driver. This
    plugin enumerates all tty_struct objects and checks if their ops handlers
    have been subverted.
    

epydoc: rekall.plugins.linux.check_tty.CheckTTY-class.html
---
