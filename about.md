---
layout: default
order: 2
menuitem: About
title: Rekall Memory Forensic Framework
---

## Licensing and Copyright

Copyright (C) 2007-2011 Volatile Systems

Copyright 2013 Google Inc. All Rights Reserved.

All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

## History

In December 2011, a new branch within the Volatility project was created to
explore how to make the code base more modular, improve performance, and
increase usability. The modularity allowed Volatility to be used in GRR, making
memory analysis a core part of a strategy to enable remote live forensics.  As a
result, both GRR and Volatility would be able to use each others’ strengths.

Over time this branch has become known as the "scudette" branch or the
"Technology Preview" branch.  It was always a goal to try to get these changes
into the main Volatility code base.  But, after two years of ongoing
development, the "Technology Preview" was never accepted into the Volatility
trunk version.

Since it seemed unlikely these changes would be incorporated in the future, it
made sense to develop the Technology Preview branch as a separate project. On
December 13, 2013, the former branch was forked to create a new stand-alone
project named "Rekall.” This new project incorporates changes made to streamline
the codebase so that Rekall can be used as a library. Methods for memory
acquisition and other outside contributions have also been included that were
not in the Volatility codebase.

Rekall strives to advance the state of the art in memory analysis, implementing
the best algorithms currently available and a complete memory acquisition and
analysis solution for at least Windows, OSX and Linux.
