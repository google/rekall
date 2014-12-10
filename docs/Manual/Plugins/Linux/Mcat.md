---
layout: plugin
title: mcat
abstract: |
  Returns the contents available in memory for a given file.
  
  Ranges of the file that are not present in memory are returned blank.

epydoc: rekall.plugins.linux.fs.Mcat-class.html
args:
  out_file: 'Path for output file.'
  path: 'Path to the file.'
  device: 'Name of the device to match.'
  dtb: 'The DTB physical address.'

---

You can find the list of files in memory by using the `mls` plugin.
