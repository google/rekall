---
abstract: Dump the entire resolver contents for an AFF4 volume.
args: {gce_credentials: 'The GCE service account credentials to use. (type: String)

    ', gce_credentials_path: 'A path to the GCE service account credentials to use.
    (type: String)

    ', long: 'Include additional information about each stream. (type: Boolean)

    ', regex: 'Regex of filenames to dump. (type: RegEx)



    * Default: .', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1', volume: 'Volume to list. (type: String)

    '}
class_name: AFF4Dump
epydoc: rekall.plugins.tools.aff4acquire.AFF4Dump-class.html
layout: plugin
module: rekall.plugins.tools.aff4acquire
title: aff4dump
---
