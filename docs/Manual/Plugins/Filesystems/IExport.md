---
abstract: "Extracts files from NTFS.\n\n    For each specified MFT entry, dump the\
  \ file to the specified dump\n    directory. The filename is taken as the longest\
  \ filename of this MFT entry.\n    "
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', id: 'Id of attribute to dump. (type: IntParser)

    ', mft: 'MFT entry to dump. (type: IntParser)



    * Default: 5', type: 'Attribute type to dump. (type: IntParser)



    * Default: 128', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: IExport
epydoc: rekall.plugins.filesystems.ntfs.IExport-class.html
layout: plugin
module: rekall.plugins.filesystems.ntfs
title: iexport
---
