---
abstract: "Prints various information about a query.\n\n    Explains how a query was\
  \ parsed and how it will be interpreted. It also\n    runs a full type inferencer,\
  \ to attempt to determine the output of the\n    query once it's executed.\n\n \
  \   The Explain plugin can analyse a strict superset of expressions that\n    are\
  \ valid in the Search plugin. It supports:\n\n     - Any search query that can be\
  \ passed to Search.\n     - Expressions asking about types and members of profile\
  \ types\n       (like structs).\n    "
args: {query: The dotty/EFILTER query to run., query_parameters: 'Positional parameters
    for parametrized queries. (type: ArrayStringParser)



    * Default: '}
class_name: Explain
epydoc: rekall.plugins.common.search.Explain-class.html
layout: plugin
module: rekall.plugins.common.search
title: explain
---
