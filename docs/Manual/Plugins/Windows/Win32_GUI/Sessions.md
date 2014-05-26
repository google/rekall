
---
layout: plugin
title: sessions
abstract: |
    List details on _MM_SESSION_SPACE (user logon sessions).

    Windows uses sessions in order to separate processes. Sessions are used to
    separate the address spaces of windows processes.

    Note that this plugin traverses the ProcessList member of the session object
    to list the processes - yet another list _EPROCESS objects are on.
    

epydoc: rekall.plugins.windows.gui.sessions.Sessions-class.html
---
