---
abstract: "Search for files by filename glob.\n\n    This code roughly based on the\
  \ Glob flow in GRR.\n    "
args: {case_insensitive: 'Globs will be case insensitive. (type: Bool)



    * Default: True', filesystem: "The virtual filesystem implementation to glob in.\
    \ (type: Choices)\n\n\n* Valid Choices:\n    - API\n\n\n* Default: API", globs: 'List
    of globs to return. (type: ArrayString)

    ', path_sep: 'Path separator character (/ or \) (type: String)

    ', root: 'Root directory to glob from. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: IRGlob
epydoc: rekall.plugins.response.files.IRGlob-class.html
layout: plugin
module: rekall.plugins.response.files
title: glob
---
