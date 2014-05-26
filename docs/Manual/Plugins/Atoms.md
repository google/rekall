
---
layout: plugin
title: atoms
abstract: |
    Print session and window station atom tables.

    From:
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms649053.aspx

    An atom table is a system-defined table that stores strings and
    corresponding identifiers. An application places a string in an atom table
    and receives a 16-bit integer, called an atom, that can be used to access
    the string. A string that has been placed in an atom table is called an atom
    name.

    The global atom table is available to all applications. When an application
    places a string in the global atom table, the system generates an atom that
    is unique throughout the system. Any application that has the atom can
    obtain the string it identifies by querying the global atom table.

    (The global atom tables are only global within each session).
    

epydoc: rekall.plugins.windows.gui.atoms.Atoms-class.html
---
