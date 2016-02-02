---
abstract: "Checks tty devices for hooks.\n\n    Some malware insert a hook into the\
  \ ops struct of the tty driver. This\n    plugin enumerates all tty_struct objects\
  \ and checks if their ops handlers\n    have been subverted.\n    "
args: {}
class_name: CheckTTY
epydoc: rekall.plugins.linux.check_tty.CheckTTY-class.html
layout: plugin
module: rekall.plugins.linux.check_tty
title: check_ttys
---
