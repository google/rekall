---
abstract: "Searches and recombines output of other plugins.\n\n    Search allows you\
  \ to use the EFILTER search engine to filter, transform\n    and combine output\
  \ of most Rekall plugins. The most common use for this\n    is running IOCs.\n\n\
  \    Some examples that work right now:\n    ==================================\n\
  \n    # Find the process with pid 1:\n    search(\"select * pslist() where proc.pid\
  \ == 1\")\n\n    # Sort lsof output by file descriptor:\n    search(\"sort(lsof(),\
  \ fd)\") # or:\n    search(\"select * from lsof() order by fd)\")\n\n    # Filter\
  \ and sort through lsof in one step:\n    search(\"select * from lsof() where proc.pid\
  \ == 1 order by fd)\n\n    # Is there any proc with PID 1, that has a TCPv6 connection\
  \ and isn't a\n    # dead process?\n    search(\"(any lsof where (proc.pid == 1\
  \ and fileproc.human_type == 'TCPv6'))\n             and not (any dead_procs where\
  \ (proc.pid == 1))\")\n\n    # Note: \"ANY\" is just a short hand for \"SELECT ANY\
  \ FROM\" which does what\n    # it sounds like, and returns True or False depending\
  \ on whether the\n    # query has any results.\n    "
args: {query: 'The dotty/EFILTER query to run. (type: String)

    ', query_parameters: 'Positional parameters for parametrized queries. (type: ArrayString)

    ', silent: 'Queries should fail silently. (type: Boolean)



    * Default: False'}
class_name: Search
epydoc: rekall.plugins.common.efilter_plugins.search.Search-class.html
layout: plugin
module: rekall.plugins.common.efilter_plugins.search
title: search
---
