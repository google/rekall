
---
layout: plugin
title: build_index
abstract: |
    Generate a profile index file based on an index specification.

    The index specification is currently a yaml file with the following
    structure:

    - repository_path: The path to the repository to index.
    - symbols: # A list of symbols to index.
       name: Symbol name.
       data: Data that should be found in the image.

    Example:

    ```
    repository_root: ./
    path: win32k.sys
    symbols:
      -
        # The name of the symbol we test for.
        name: "??_C@_1BO@KLKIFHLC@?$AAG?$AAU?$AAI?$AAF?$AAo?$AAn?$AAt?$AA?4?$AAH?$AAe?$AAi?$AAg?$AAh?$AAt?$AA?$AA@"

        # The data we expect to find at that offset.
        data: "47005500490046006f006e0074002e00480065006900670068007400"

      -
        name: "wcschr"
        shift: -1
        data: "90"
    ```

    The result is an index profile. This has an $INDEX section which is a dict,
    with keys being the profile name, and values being a list of (offset, match)
    tuples.

epydoc: rekall.plugins.tools.profile_tool.BuildIndex-class.html
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

