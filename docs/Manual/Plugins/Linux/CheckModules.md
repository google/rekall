---
abstract: "Compares module list to sysfs info, if available.\n\n    Sysfs contains\
  \ a kset objects for a number of kernel objects (kobjects). One\n    of the ksets\
  \ is the \"module_kset\" which holds references to all loaded\n    kernel modules.\n\
  \n    Each struct module object holds within it a kobj struct for reference\n  \
  \  counting. This object is referenced both from the struct module and the\n   \
  \ sysfs kset.\n\n    This plugin traverses the kset and resolves the kobj back to\
  \ its containing\n    object (which is the struct module itself). We then compare\
  \ the struct\n    module with the list of known modules (which is obtained by traversing\
  \ the\n    module's list member). So if a module were to simply unlink itself from\
  \ the\n    list, it would still be found by its reference from sysfs.\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: CheckModules
epydoc: rekall.plugins.linux.check_modules.CheckModules-class.html
layout: plugin
module: rekall.plugins.linux.check_modules
title: check_modules
---
