---
title: Pmem- Linux Acquisition tool.
---

# Pmem: Linux Acquisition tools.

This directory contains two tools for memory acquisition on linux platforms:

* The pmem tool is a simple kernel driver for physical memory acquisition. It
  needs to be built on a linux system which kernel headers matching the acquired
  kernel.

* The LMAP (Linux Memory Acquisition Parasite) is an advanced linux memory acquisition tool which does not need to be compiled in advance. See [LMAP] for details.

[LMAP]: /docs/References/Presentations/LMAP-DFRWS_EU_2014.html