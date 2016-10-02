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

"""Implements file download client actions."""
from rekall.plugins.response import common
from rekall_agent import common as agent_common
from rekall_agent import location
from rekall_agent.client_actions import collect
from rekall_agent.client_actions import files


class GetFiles(collect.CollectAction):
    """Upload files to the remote storage location.

    """
    schema = [
        dict(name="collection", type=files.StatEntryCollection,
             doc="A StatEntryCollection to store the results in."),

        dict(name="location", type=location.Location,
             doc="A location to store the files.")
    ]

    def collect(self):
        """Intercept collected rows and detect any files."""
        self._to_download = []
        for row in super(GetFiles, self).collect():
            if not self.location:
                # If we are not downloading the files report all hits.
                yield row
                continue

            # If we are uploading the files, then only reports the files we
            # uploaded.

            # Try to detect files as any column with an instance of FileSpec.
            for path in row.itervalues():
                if isinstance(path, common.FileSpec):
                    file_info = common.FileInformation.from_stat(
                        path, session=self._session)
                    try:
                        # Its a real file, save it for later uploading.
                        if not file_info.st_mode.is_dir():
                            fd = file_info.open()
                            self._to_download.append(
                                dict(fd=fd, subpath=path.name))

                            yield row
                    except IOError:
                        self._session.logging.info(
                            "Unable to upload %s", path.filename.name)

    def run(self):
        """If files were emitted by the collection, upload them all now."""
        result = super(GetFiles, self).run()

        if self._to_download:
            try:
                # Wait until all the uploads are done before we return.
                list(agent_common.THREADPOOL.imap_unordered(
                    lambda kw: self.location.upload_file_object(**kw),
                    self._to_download))
            finally:
                for kw in self._to_download:
                    kw["fd"].close()

        return result
