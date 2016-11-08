---
abstract: "Shows the parent/child relationship between processes.\n\n    This plugin\
  \ prints a parent/child relationship tree by walking the\n    task_struct.children\
  \ and task_struct.sibling members.\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LinPSTree
epydoc: rekall.plugins.linux.pstree.LinPSTree-class.html
layout: plugin
module: rekall.plugins.linux.pstree
title: pstree
---
