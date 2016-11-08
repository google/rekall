---
abstract: Exports all the streams in an AFF4 Volume.
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', gce_credentials: 'The GCE service account credentials to use. (type: String)

    ', gce_credentials_path: 'A path to the GCE service account credentials to use.
    (type: String)

    ', regex: 'Regex of filenames to dump. (type: RegEx)



    * Default: .', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1', volume: 'Volume to list. (type: String)

    '}
class_name: AFF4Export
epydoc: rekall.plugins.tools.aff4acquire.AFF4Export-class.html
layout: plugin
module: rekall.plugins.tools.aff4acquire
title: aff4export
---
