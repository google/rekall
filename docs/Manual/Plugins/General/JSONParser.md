
---
layout: plugin
title: json_render
abstract: |
    Renders a json rendering file, as produced by the JsonRenderer.

    The output of any plugin can be stored to a JSON file using:

    rekall -f img.dd --renderer JsonRenderer plugin_name --output test.json

    Then it can be rendered again using:

    rekall json_render test.json

    This plugin implements the proper decoding of the JSON encoded output.
    

epydoc: rekall.plugins.tools.json_tools.JSONParser-class.html
---
