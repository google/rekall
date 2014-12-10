---
layout: plugin
title: find
abstract: |
  Runs the query and displays results. Base class for saved searches.
  
      This class is designed to be subclasses by saved searches. Subclasses may
      override the defaults for the following properties:
  
      --query, search: The query that'll be run.
      (--)display_filter: Another query that'll be used to filter out unwanted
                          results.
      (--)columns: A list of attributes to render in the output. Format as
                   "Component/attribute".
      (--)sort: A list of columns to sort by. Sort is currently ASC. Same format
                as above.
      (--)width: Width of the rendered table.
      (--)stream_results: If on, will render results as soon as they're available.
                          This typically means the results will be incomplete. It
                          is probably pointless to use this in combination with
                          'sort' but no one will stop you.
  
      Further arguments that can be supplied at runtime:
  
      --explain: If set, an analysis of the query will be rendered and each
                 row in results will include a highlight of the part of the query
                 that matched it (obviously a heuristic, your mileage may vary).

epydoc: rekall.plugins.common.entities.EntityFind-class.html
args:
  query: 'The filter query to use.'
  explain: 'Show which part of the query matched.'
  columns: ''
  sort: ''
  width: ''
  filter: ''
  stream_results: ''

---

