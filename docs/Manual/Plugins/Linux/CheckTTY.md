---
abstract: "Checks tty devices for hooks.\n\n    Some malware insert a hook into the\
  \ ops struct of the tty driver. This\n    plugin enumerates all tty_struct objects\
  \ and checks if their ops handlers\n    have been subverted.\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: CheckTTY
epydoc: rekall.plugins.linux.check_tty.CheckTTY-class.html
layout: plugin
module: rekall.plugins.linux.check_tty
title: check_ttys
---
