from __future__ import division
# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
# Michael Cohen <scudette@gmail.com>
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

from past.utils import old_div
import os

from rekall import plugin
from rekall import testlib
from rekall_lib import utils


class ImageCopy(plugin.PhysicalASMixin, plugin.Command):
    """Copies a physical address space out as a raw DD image"""

    __name = "imagecopy"

    @classmethod
    def args(cls, parser):
        super(ImageCopy, cls).args(parser)

        parser.add_argument("-O", "--output-image", default=None,
                            help="Filename to write output image.")

    def __init__(self, output_image=None, address_space=None, **kwargs):
        """Dumps the address_space into the output file.

        Args:
          output_image: The output filename.

          address_space: The address space to dump. If not specified, we use the
          physical address space.
        """
        super(ImageCopy, self).__init__(**kwargs)
        self.output_image = output_image
        if address_space is None:
            # Use the physical address space.
            if self.session.physical_address_space is None:
                self.session.plugins.load_as()

            address_space = self.session.physical_address_space

        if address_space is None:
            raise plugin.PluginError("No valid address space was found.")

        self.address_space = address_space

    def human_readable(self, value):
        for i in ['B', 'KB', 'MB', 'GB']:
            if value < 800:
                return "{0:0.2f} {1:s}".format(value, i)
            value = old_div(value, 1024.0)

        return "{0:0.2f} TB".format(value)

    def render(self, renderer):
        """Renders the file to disk"""
        if self.output_image is None:
            raise plugin.PluginError("Please provide an output-image filename")

        if (os.path.exists(self.output_image) and
                os.path.getsize(self.output_image) > 1):
            raise plugin.PluginError("Refusing to overwrite an existing file, "
                                     "please remove it before continuing")

        blocksize = 1024 * 1024 * 5
        with renderer.open(filename=self.output_image, mode="wb") as fd:
            for run in self.address_space.get_mappings():
                self.session.report_progress(
                    "Range %x - %x", run.start, run.length)

                for offset in utils.xrange(
                        run.start, run.end, blocksize):
                    to_read = min(blocksize, run.end - offset)
                    data = self.address_space.read(offset, to_read)

                    if offset > 500e9:
                        break

                    fd.seek(offset)
                    fd.write(data)

                    renderer.RenderProgress(
                        "Writing offset %s" % self.human_readable(offset))


class TestImageCopy(testlib.HashChecker):
    PARAMETERS = dict(commandline="imagecopy -O %(tempdir)s/output_image.raw")
