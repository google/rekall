---
abstract: "Renders a json rendering file, as produced by the JsonRenderer.\n\n   \
  \ The output of any plugin can be stored to a JSON file using:\n\n    rekall -f\
  \ img.dd --format json plugin_name --output test.json\n\n    Then it can be rendered\
  \ again using:\n\n    rekall json_render test.json\n\n    This plugin implements\
  \ the proper decoding of the JSON encoded output.\n    "
args: {file: The filename to parse.}
class_name: JSONParser
epydoc: rekall.plugins.tools.json_tools.JSONParser-class.html
layout: plugin
module: rekall.plugins.tools.json_tools
title: json_render
---
