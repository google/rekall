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
from rekall import cache
from rekall import config
from rekall import io_manager


config.DeclareOption(
    "cache_dir", default=None,
    help="Location of the profile cache directory.")


class CachingManager(io_manager.IOManager):

    # We wrap this io manager class
    DELEGATE = io_manager.URLManager

    # If the cache is available we should be selected before the regular
    # manager.
    order = DELEGATE.order - 10

    def __init__(self, session=None, **kwargs):
        super(CachingManager, self).__init__(session=session, **kwargs)

        cache_dir = cache.GetCacheDir(session)

        # We use an IO manager to manage the cache directory directly.
        self.cache_io_manager = io_manager.DirectoryIOManager(urn=cache_dir,
                                                              session=session)
        self.url_manager = self.DELEGATE(session=session, **kwargs)

        self.CheckUpstreamRepository()

    def __str__(self):
        return "Local Cache %s" % self.cache_io_manager

    def CheckInventory(self, name):
        if self.cache_io_manager.CheckInventory(name):
            return True

        return self.url_manager.CheckInventory(name)

    def GetData(self, name, **kwargs):
        if self.cache_io_manager.CheckInventory(name):
            local_age = self.cache_io_manager.Metadata(name).get(
                "LastModified", 0)
            remote_age = self.url_manager.Metadata(name).get("LastModified", 0)

            # Only get the local copy if it is not older than the remote
            # copy. This allows the remote end to update profiles and we will
            # automatically pick the latest.
            if local_age >= remote_age:
                data = self.cache_io_manager.GetData(name)
                # Ensure our local cache looks reasonable.
                if data.get("$METADATA"):
                    return data

        # Fetch the data from our base class and store it in the cache.
        data = self.url_manager.GetData(name, **kwargs)

        # Only store the data in the cache if it looks reasonable. Otherwise we
        # will trash the cache with bad data in case we can not access correct
        # data.
        if data and data.get("$METADATA"):
            self.session.logging.debug("Adding %s to local cache.", name)
            self.cache_io_manager.StoreData(name, data)

        return data

    def StoreData(self, name, data, **options):
        self.cache_io_manager.StoreData(name, data, **options)

    def CheckUpstreamRepository(self):
        """Checks the repository for freshness."""
        upstream_inventory = self.url_manager.inventory

        # This indicates failure to contact the remote repository. In this case
        # we do not want to invalidate our cache, just use the cache as is.
        if not self.url_manager.ValidateInventory():
            self.session.logging.warn(
                "Repository %s will be disabled.", self.urn)
            raise ValueError("Invalid inventory.")

        cache_inventory = self.cache_io_manager.inventory
        modified = False

        for item, metadata in cache_inventory.get("$INVENTORY", {}).items():
            upstream_meta = upstream_inventory.get(
                "$INVENTORY", {}).get(item)

            if (upstream_meta is None or
                    upstream_meta["LastModified"] > metadata["LastModified"]):
                cache_inventory["$INVENTORY"].pop(item)
                modified = True

        if modified:
            self.cache_io_manager.FlushInventory()

    def ListFiles(self):
        return self.url_manager.ListFiles()


class CacheDirectoryManager(CachingManager):
    DELEGATE = io_manager.DirectoryIOManager
