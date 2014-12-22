#!/usr/bin/python

# Rekall
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This file implements a caching URL manager.

We locally cache selected files from the remote profile repository. If a profile
is not found in the local cache, we retrieve it from the remote repository, and
add it to the cache.

We check the remote repository for staleness and update the local cache in the
background.
"""

__author__ = "Michael Cohen <scudette@google.com>"

import os

from rekall import config
from rekall import io_manager


config.DeclareOption(
    "cache_dir", default=None,
    help="Location of the profile cache directory.")


class CachingURLManager(io_manager.IOManager):
    # If the cache is available we should be selected before the regular
    # URLManager.
    order = io_manager.URLManager.order - 10

    def __init__(self, session=None, **kwargs):
        cache_dir = session.GetParameter("cache_dir")

        if not cache_dir:
            raise io_manager.IOManagerError(
                "Local profile cache is not configured - "
                "add a cache_dir parameter to ~/.rekallrc.")

        # Cache dir may be specified relative to the home directory.
        cache_dir = os.path.join(config.GetHomeDir(), cache_dir)
        if not os.access(cache_dir, os.F_OK | os.R_OK | os.W_OK | os.X_OK):
            try:
                os.makedirs(cache_dir)
            except (IOError, OSError):
                raise io_manager.IOManagerError(
                    "Unable to create or access cache directory %s" % cache_dir)

        # We use an IO manager to manage the cache directory directly.
        self.cache_io_manager = io_manager.DirectoryIOManager(urn=cache_dir)
        self.url_manager = io_manager.URLManager(session=session, **kwargs)

        self.CheckUpstreamRepository()

        super(CachingURLManager, self).__init__(session=session, **kwargs)

    def __str__(self):
        return "Local Cache %s" % self.cache_io_manager

    def CheckInventory(self, name):
        if self.cache_io_manager.CheckInventory(name):
            return True

        return self.url_manager.CheckInventory(name)

    def GetData(self, name, **kwargs):
        if self.cache_io_manager.CheckInventory(name):
            return self.cache_io_manager.GetData(name)

        # Fetch the data from our base class and store it in the cache.
        data = self.url_manager.GetData(name, **kwargs)
        self.cache_io_manager.StoreData(name, data)

        return data

    def CheckUpstreamRepository(self):
        """Checks the repository for freshness."""
        upstream_inventory = self.url_manager.inventory
        cache_inventory = self.cache_io_manager.inventory
        modified = False

        for item, metadata in cache_inventory["$INVENTORY"].items():
            upstream_meta = upstream_inventory.get(
                "$INVENTORY", {}).get(item)

            if (upstream_meta is None or
                    upstream_meta["LastModified"] > metadata["LastModified"]):
                cache_inventory["$INVENTORY"].pop(item)
                modified = True

        if modified:
            self.cache_io_manager.FlushInventory()
