---
abstract: "\n    Print list of open sockets. [Windows xp only]\n    ---------------------------------------------\n\
  \n    This module enumerates the active sockets from tcpip.sys\n\n    Note that\
  \ if you are using a hibernated image this might not work\n    because Windows closes\
  \ all sockets before hibernating.\n\n    _ADDRESS_OBJECT are arranged in a hash\
  \ table found by the _AddrObjTable\n    symbol. The hash table has a size found\
  \ by the _AddrObjTableSize symbol.\n    "
args: {tcpip_guid: Force this profile to be used for tcpip.}
class_name: Sockets
epydoc: rekall.plugins.windows.connections.Sockets-class.html
layout: plugin
module: rekall.plugins.windows.connections
title: sockets
---
  
  This module enumerates the active sockets from tcpip.sys
  
  Note that if you are using a hibernated image this might not work
  because Windows closes all sockets before hibernating.
  
  _ADDRESS_OBJECT are arranged in a hash table found by the _AddrObjTable
  symbol. The hash table has a size found by the _AddrObjTableSize symbol.

epydoc: rekall.plugins.windows.connections.Sockets-class.html
args:
  tcpip_guid: 'Force this profile to be used for tcpip.'

---

