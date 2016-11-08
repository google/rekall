---
abstract: "Loads the profile into the session.\n\n    If the profile does not exist\
  \ in the repositories, fetch and build it from\n    the symbol server. This plugin\
  \ allows the user to change resolution of\n    selected binaries by forcing the\
  \ fetching of symbol files from the symbol\n    server interactively.\n    "
args: {guid: 'The guid of the module. (type: String)

    ', module_name: 'The name of the module (without the .pdb extensilon). (type:
    String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LoadWindowsProfile
epydoc: rekall.plugins.windows.interactive.profiles.LoadWindowsProfile-class.html
layout: plugin
module: rekall.plugins.windows.interactive.profiles
title: load_profile
---
