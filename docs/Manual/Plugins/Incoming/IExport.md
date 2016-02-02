---
abstract: "Extracts files from NTFS.\n\n    For each specified MFT entry, dump the\
  \ file to the specified dump\n    directory. The filename is taken as the longest\
  \ filename of this MFT entry.\n    "
args: {dump_dir: 'Path suitable for dumping files. (Default: Use current directory)',
  id: 'Id of attribute to dump. (type: IntParser)

    ', mft: 'MFT entry to dump. (type: IntParser)



    * Default: 5', type: 'Attribute type to dump. (type: IntParser)



    * Default: 128'}
class_name: IExport
epydoc: rekall.plugins.filesystems.ntfs.IExport-class.html
layout: plugin
module: rekall.plugins.filesystems.ntfs
title: iexport
---
