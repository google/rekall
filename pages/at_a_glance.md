---
layout: default
title: Rekall at a glance.
author: Michael Cohen <scudette@gmail.com>
---

# Rekall at a glance.

Memory forensics has been a hot topic for the last few years, and indeed there
are a number of other memory analysis frameworks out there. What sets Rekall
apart from those?

### Memory analysis and live analysis

Rekall strives to be a complete end-to-end memory analysis framework,
encapsulating acquisition, analysis, and reporting. Because we also write memory
acquisition tools, we can exploit synergies between the analysis and acquisition
parts of the tool.

In particular Rekall is the only memory analysis platform specifically designed
to run on the same platform it is analyzing: Live analysis allows us to
corroborate memory artifacts with results obtained through system APIs, as well
as quickly triage a system without having to write out and manage large memory
images (This becomes very important for large servers where the time of
acquisition leads to too much smear).

We also ensure our memory analysis tools are stable and work on all supported
platforms (For example Rekall features the only memory imaging tool available
for recent versions of OSX, that we know of - and it is open source and free as
well!).

### Fully usable as a library.

One of the major goals of Rekall is to make it possible to embed Rekall as a
library inside another project. To make Rekall library friendly we added a
suspension/progress API where Rekall can inform callers about its progress (this
is useful for UI applications which must return to their main loop very
frequently).

Rekall also has support for customized output formats. One of the more useful
formats is a JSON based data export format. Thus the output of Rekall can easily
be consumed inside another program - even one written in a different language.

### An advanced GUI.

Old school forensics analysts are used to work with standard UNIX tools and text
based output. When we wanted to add a GUI to Rekall we wanted something which
would be genuinely more useful than simple text output in a web page. We were
inspired by the IPython notebook to create a new kind of GUI for Rekall: The
webconsole worksheet.

The Worksheet is truly a useful GUI - it allows the analyst to create a report,
merging marked up text, images, embedded files, shell and python code snippets
as well as the output of Rekall plugins in the same document. Rekall output then
presents useful action menus which help to drive the analysis by drilling down
into different objects found.

The analyst then essentially tells a story: What evidence did they look at, how
was it relevant, what was the outcome.

When we created the Rekall GUI we realized this could be a wonderful information
sharing tool - after all when we teach our memory analysis workshops we also
tell a story, with examples, text, illustrations etc. Thus the idea to create an
open source, publicly accessible forensic course was born. We have recently
launched [The Memory Analysis
Workshop](http://memory-analysis.rekall-forensic.com/) and hope it will grow
into a widely utilized resource. We use the Rekall webcosole export feature to
host a "non-interactive" version of the document, but users can also load the
full live document to interactively drill down into sample images by
themselves. Users can modify this and then submit these modification for
inclusion with a GitHub pull request.

### Using symbols.

One of the main differences between Rekall and other memory analysis frameworks
is that Rekall uses symbols obtained from operating system vendors' debugging
information directly. This allows Rekall to just know the position of critical
operating system constants, while other frameworks employ fragile scanning
techniques to locate these symbols. Scanning techniques are notorious for being
fragile, and malware can easily maliciously interfere with those by removing or
adding spurious signatures.

A side effect of this feature, is that writing a plugin in Rekall is much
simpler - one simply asks the framework for the location of the required global
constant, and goes on to use it, instead of writing a new kind of scanner for
each global symbol. Additionally we simplified the API greatly to make plugin
writing a real breeze.

### Looking to the future.

Rekall is already a powerful memory analysis framework, but where do we want to
take it?

One of the biggest problems with many of the current set of plugins is that
there are so many of them! Each plugin checks for something specific and
understanding what the output means is very plugin dependent and requires a deep
understanding of what the plugin is actually doing. This does not scale for
automated analysis.

We want to improve the situation by treating memory analysis as a search
problem: Imagine if you can simply run a bunch of searches in a "SQL like"
language which just gives a set of possible suspicious Entities (e.g. Processes,
sockets etc). Now imagine scaling this up to every machine in an enterprise
using [GRR](https://github.com/google/grr). Now imagine having a library of such
"indicators" to use and share?

In order to run useful hunts across thousands of machines we need to make memory
analysis more automated. It has to be more flexible - we can not write a new
plugin for every new strand of malware we see, instead we need to have a search
language expressive enough to be able to capture the essence of each malware
signal.

This effort is currently available with OSX analysis but we hope to make this
feature available across all operating systems in future.
