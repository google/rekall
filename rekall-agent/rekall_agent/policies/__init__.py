#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

__author__ = "Michael Cohen <scudette@google.com>"

"""The Rekall Agent relies on transferring files between client and server.

The decision about where files should be placed, where the agent expects them to
be and how they are tranferred is termed the "Policy".

There are a number of policies implemented via different policy classes
(extending agent.ServerPolicy and agent.ClientPolicy). The Policy objects tie
abstract concepts into concrete implementations.

For example the agent has an abstract concept of a jobs queue (the queue which
job requests come in on). The policy object returns a Location instance to
indicate where jobs are to be read from. Depending on the policy this can come
from static files, static web pages, pub/sub queues etc.
"""

from rekall_agent.policies import files
from rekall_agent.policies import gcs
