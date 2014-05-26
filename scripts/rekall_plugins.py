from rekall import plugins
from rekall import plugin
import os

for cls in plugin.Command.classes.values():
    doc = cls.__doc__ or ""
    result = dict(layout="plugin", title=cls.name,
                  abstract=doc,
                  epydoc="%s.%s-class.html" % (
                      cls.__module__, cls.__name__))

    filename = "%s.md" % cls.__name__
    if not os.access(filename, os.EX_OK):
        with open(filename, "wb") as fd:
            data = """---
layout: plugin
title: %(title)s
abstract: |
    %(abstract)s

epydoc: %(epydoc)s
---
""" % result
            fd.write(data)
