---
layout: images
title: Rekall GUI
image_path: docs/GUI/
---

# The Rekall interactive web console.

Rekall now has a fully functioning interactive web console. Traditionally us
hard core forensic analysts tend to shy from GUIs. So when we set out to write a
GUI for Rekall we didn't want it to just be pretty but we wanted to make the GUI
improve the analysis workflow and make it easier to share the results. We were
sick of running the same plugin on the same image many times, grepping for
results and viewing everything through "less".

## Starting up the web console.

The web console uses a directory to place its files. It therefore needs to be
started with a path to an existing directory. You can make an empty directory
first, or simply use an existing Rekall directory. On windows, the installer
creates a file association with the `metadata.rkl` file within the web console
to automatically open the directory.

```sh
$ mkdir /tmp/my_worksheet/
$ rekal webconsole --browser /tmp/my_worksheet/
```

This will start the server on a random port (the server is bound to the loopback
interface by default) and then spawn a new browser window to view it. You can
use the `--port` argument to specify a specific port.

NOTE: The Rekall web console provides arbitrary code execution through the
`shell` and `pythoncode` cell types. Do not expose the web console to untrusted
users. Ensure the adequate security is provided (either by restricting access to
localhost, or by restricting access via iptable rules, or additional
authentication+SSL).

The first thing you should do is configure the first session by clicking on the
"Session" button. You can add the image filename and also name the session here.

## Screenshots
