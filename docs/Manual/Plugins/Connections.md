
---
layout: plugin
title: connections
abstract: |

    Print list of open connections [Windows XP Only]
    ---------------------------------------------

    This module enumerates the active connections from tcpip.sys.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.

    Active TCP connections are found in a hash table. The Hash table is given by
    the _TCBTable symbol. The size of the hash table is found in the
    _MaxHashTableSize variable.


epydoc: rekall.plugins.windows.connections.Connections-class.html
---
