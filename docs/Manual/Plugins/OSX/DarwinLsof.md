---
abstract: "Walks open files of each proc in order and prints PID, FD and the handle.\n\
  \n    Each process has an array of pointers to fileproc structs - the offset into\n\
  \    the array is the file descriptor and each fileproc struct represents a\n  \
  \  handle on some resource. A type field in the fileproc determines the type\n \
  \   of the resource pointed to from the fileproc (e.g. vnode, socket, pipe...).\n\
  \    "
args: {}
class_name: DarwinLsof
epydoc: rekall.plugins.darwin.lsof.DarwinLsof-class.html
layout: plugin
module: rekall.plugins.darwin.lsof
title: lsof
---
