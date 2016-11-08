---
abstract: "Prints all open sockets we know about, from any source.\n\n    Netstat\
  \ will display even connections that lsof doesn't know about, because\n    they\
  \ were either recovered from an allocation zone, or found through a\n    secondary\
  \ mechanism (like system call handler cache).\n\n    On the other hand, netstat\
  \ doesn't know the file descriptor or, really, the\n    process that owns the connection\
  \ (although it does know the PID of the last\n    process to access the socket.)\n\
  \n    Netstat will also tell you, in the style of psxview, if a socket was only\n\
  \    found using some of the methods available.\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinNetstat
epydoc: rekall.plugins.darwin.networking.DarwinNetstat-class.html
layout: plugin
module: rekall.plugins.darwin.networking
title: netstat
---
