---
layout: download
menuitem: Releases
title: Version 1.5.2 Furka..
order: 2
---

# Rekall Memory Forensic Releases

This is the next point release in the 1.5 (Furka) series.

Some highlights of this release:

* Rekall had obtained many live plugins for Incident Response:

  * glob, wmi, registry yara scanning of files etc. This capability makes Rekall
    a capable tool for incident response and triaging.

* EFilter is now better integrated. Users can simple run SQL queries directly in
    the console.

* Artifact collector allows Rekall to use the forensic artifacts project
    (https://github.com/ForensicArtifacts/artifacts)


As always install with pip and virtualenv:

```
$ virtualenv /path/to/env
$ source /path/to/env/bin/activate
$ pip install --upgrade pip setuptools wheel
$ pip install rekall
```
