---
abstract: Creates a new session by cloning the current one.
args: {session_id: The session id to change to}
class_name: SessionNew
epydoc: rekall.plugins.tools.ipython.SessionNew-class.html
layout: plugin
module: rekall.plugins.tools.ipython
title: snew
---

The Rekall interactive console may be used to analyze several images at the same
time. We do this by switching sessions. Each image has a unique session, but
since none of the sessions are global, we can switch from one session to the
next.

Rekall's session management commands can be used to switch between sessions.

The example below shows us loading a second session with a new image. We switch
to the new session and list processes in it. We then switch back and delete the
new session. Note how the prompt changes as we switch from one session to the
other.

```text
[1] win7.elf 23:55:46> snew filename="/home/scudette/images/win10.aff4"
Created session [2] /home/scudette/images/win10.aff4 (2)
               Out<61> Plugin: snew
[2] /home/scudette/images/win10.aff4 (2) 23:57:03> pslist
-------------------------------------------------> pslist()
  _EPROCESS            Name          PID   PPID   Thds    Hnds    Sess  Wow64           Start                     Exit
-------------- -------------------- ----- ------ ------ -------- ------ ------ ------------------------ ------------------------
0xe0003486d680 System                   4      0     82        -      - False  2015-06-03 06:56:02Z     -
0xe00035e54040 smss.exe               260      4      2        -      - False  2015-06-03 06:56:02Z     -
0xe00035b84080 csrss.exe              332    324      9        -      0 False  2015-06-03 06:56:03Z     -
0xe0003489b280 wininit.exe            400    324      1        -      0 False  2015-06-03 06:56:03Z     -
[2] /home/scudette/images/win10.aff4 (2) 23:57:09> sswitch 1
                                           Out<63> Plugin: sswitch
[1] win7.elf 23:57:12> pslist
---------------------> pslist()
  _EPROCESS            Name          PID   PPID   Thds    Hnds    Sess  Wow64           Start                     Exit
-------------- -------------------- ----- ------ ------ -------- ------ ------ ------------------------ ------------------------
0xfa80008959e0 System                   4      0     84      511      - False  2012-10-01 21:39:51Z     -
0xfa80024f85d0 svchost.exe            236    480     19      455      0 False  2012-10-01 14:40:01Z     -
0xfa8001994310 smss.exe               272      4      2       29      - False  2012-10-01 21:39:51Z     -
0xfa8002259060 csrss.exe              348    340      9      436      0 False  2012-10-01 21:39:57Z     -
[2] /home/scudette/images/win10.aff4 (2) 23:57:25> slist
  [1] win7.elf
* [2] /home/scudette/images/win10.aff4 (2)
                                           Out<68> Plugin: slist
[1] win7.elf 23:57:33> sdel 2
               Out<70> Plugin: sdel
[1] win7.elf 00:01:49> slist
* [1] win7.elf
               Out<73> Plugin: slist
```
