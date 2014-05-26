
---
layout: plugin
title: sysctl
abstract: |
    Dumps the sysctl database.

    On OSX the kernel is configured through the sysctl mechanism. This is
    analogous to /proc or /sysfs on Linux. The configuration space is broken
    into MIBs - or hierarchical namespace.

    https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/sysctl.8.html

    For example:

    net.inet.ip.subnets_are_local
    net.inet.ip.ttl
    net.inet.ip.use_route_genid

    This is implemented via a singly linked list of sysctl_oid structs. The
    structs can be on the following types:

    - CTLTYPE_INT     means this MIB will handle an int.
    - CTLTYPE_STRING  means this MIB will handle a string.
    - CTLTYPE_QUAD    means this MIB will handle a long long int.
    - CTLTYPE_NODE means this is a node which handles a sublevel of MIBs. It is
      actually a pointer to a new sysctl_oid_list which handles the sublevel.

    

epydoc: rekall.plugins.darwin.checks.DarwinSysctl-class.html
---
