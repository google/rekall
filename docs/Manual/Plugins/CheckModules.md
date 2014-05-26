
---
layout: plugin
title: check_modules
abstract: |
    Compares module list to sysfs info, if available.

    Sysfs contains a kset objects for a number of kernel objects (kobjects). One
    of the ksets is the "module_kset" which holds references to all loaded
    kernel modules.

    Each struct module object holds within it a kobj struct for reference
    counting. This object is referenced both from the struct module and the
    sysfs kset.

    This plugin traverses the kset and resolves the kobj back to its containing
    object (which is the struct module itself). We then compare the struct
    module with the list of known modules (which is obtained by traversing the
    module's list member). So if a module were to simply unlink itself from the
    list, it would still be found by its reference from sysfs.
    

epydoc: rekall.plugins.linux.check_modules.CheckModules-class.html
---
