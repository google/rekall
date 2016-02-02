---
abstract: "Dumps the sysctl database.\n\n    On OSX the kernel is configured through\
  \ the sysctl mechanism. This is\n    analogous to /proc or /sysfs on Linux. The\
  \ configuration space is broken\n    into MIBs - or hierarchical namespace.\n\n\
  \    https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/sysctl.8.html\n\
  \n    For example:\n\n    net.inet.ip.subnets_are_local\n    net.inet.ip.ttl\n \
  \   net.inet.ip.use_route_genid\n\n    This is implemented via a singly linked list\
  \ of sysctl_oid structs. The\n    structs can be on the following types:\n\n   \
  \ - CTLTYPE_INT     means this MIB will handle an int.\n    - CTLTYPE_STRING  means\
  \ this MIB will handle a string.\n    - CTLTYPE_QUAD    means this MIB will handle\
  \ a long long int.\n    - CTLTYPE_NODE means this is a node which handles a sublevel\
  \ of MIBs. It is\n      actually a pointer to a new sysctl_oid_list which handles\
  \ the sublevel.\n\n    "
args: {}
class_name: DarwinSysctl
epydoc: rekall.plugins.darwin.checks.DarwinSysctl-class.html
layout: plugin
module: rekall.plugins.darwin.checks
title: sysctl
---
