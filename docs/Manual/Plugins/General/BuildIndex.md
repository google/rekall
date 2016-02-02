---
abstract: "Generate a profile index file based on an index specification.\n\n    The\
  \ index specification is currently a yaml file with the following\n    structure:\n\
  \n    ```\n    base_symbol: (string) # OPTIONAL Compute ALL offsets as relative\
  \ to this\n        symbol. This includes MaxOffset and MinOffset.\n    symbols:\
  \ (array of dicts) # A list of symbols to index.\n      -\n        name: (string)\
  \ # Symbol name\n        data: (string) # Data that should be at the symbol's offset\n\
  \        shift: (int) # OPTIONAL Adjust symbol offset by this number\n    ```\n\n\
  \    ## Example:\n\n    ```\n    path: win32k.sys\n    symbols:\n      -\n     \
  \   # The name of the symbol we test for.\n        name: \"??_C@_1BO@KLKIFHLC@?$AAG?$AAU?$AAI?$AAF?$AAo?$AAn?$AAt?$AA?4?$AAH?$AAe?$AAi?$AAg?$AAh?$AAt?$AA?$AA@\"\
  \n\n        # The data we expect to find at that offset.\n        data: \"47005500490046006f006e0074002e00480065006900670068007400\"\
  \n\n      -\n        name: \"wcschr\"\n        shift: -1\n        data: \"90\"\n\
  \    ```\n\n    The result is an index profile. This has an $INDEX section which\
  \ is a dict,\n    with keys being the profile name, and values being a list of (offset,\
  \ match)\n    tuples. For example:\n\n    ```\n    {\n     \"$INDEX\": {\n     \
  \ \"tcpip.sys/AMD64/6.0.6001.18000/0C1A1EC1D61E4508A33F5212FC1B37202\": [[1184600,\
  \ \"495053656344656c657465496e626f756e644f7574626f756e64536150616972\"]],\n    \
  \  \"tcpip.sys/AMD64/6.0.6001.18493/29A4DBCAF840463298F40190DD1492D02\": [[1190376,\
  \ \"495053656344656c657465496e626f756e644f7574626f756e64536150616972\"]],\n    \
  \  \"tcpip.sys/AMD64/6.0.6002.18272/7E79532FC7E349C690F5FBD16E3562172\": [[1194296,\
  \ \"495053656344656c657465496e626f756e644f7574626f756e64536150616972\"]],\n    ...\n\
  \n     \"$METADATA\": {\n      \"ProfileClass\": \"Index\",\n      \"Type\": \"\
  Profile\"\n      \"MaxOffset\": 546567\n      \"MinOffset\": 0\n      }\n     }\n\
  \    ```\n    "
args: {root: 'Repository root path.


    * Default: ./', spec: An Index specification file.}
class_name: BuildIndex
epydoc: rekall.plugins.tools.profile_tool.BuildIndex-class.html
layout: plugin
module: rekall.plugins.tools.profile_tool
title: build_index
---
For example:

```
    {
     "$INDEX": {
      "tcpip.sys/AMD64/6.0.6001.18000/0C1A1EC1D61E4508A33F5212FC1B37202": [[1184600, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
      "tcpip.sys/AMD64/6.0.6001.18493/29A4DBCAF840463298F40190DD1492D02": [[1190376, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
      "tcpip.sys/AMD64/6.0.6002.18272/7E79532FC7E349C690F5FBD16E3562172": [[1194296, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
     "$METADATA": {
      "ProfileClass": "Index",
      "Type": "Profile"
      }
     }
```

