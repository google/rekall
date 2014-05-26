
---
layout: plugin
title: sockets
abstract: |
    
    Print list of open sockets. [Windows xp only]
    ---------------------------------------------

    This module enumerates the active sockets from tcpip.sys

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating.

    _ADDRESS_OBJECT are arranged in a hash table found by the _AddrObjTable
    symbol. The hash table has a size found by the _AddrObjTableSize symbol.
    

epydoc: rekall.plugins.windows.connections.Sockets-class.html
---
