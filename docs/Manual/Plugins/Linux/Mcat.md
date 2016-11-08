---
abstract: "Returns the contents available in memory for a given file.\n\n    Ranges\
  \ of the file that are not present in memory are returned blank.\n    "
args: {device: 'Name of the device to match. (type: String)

    ', dump_dir: 'Path suitable for dumping files. (type: String)

    ', path: 'Path to the file. (type: String)



    * Default: /', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Mcat
epydoc: rekall.plugins.linux.fs.Mcat-class.html
layout: plugin
module: rekall.plugins.linux.fs
title: mcat
---

You can find the list of files in memory by using the `mls` plugin.
