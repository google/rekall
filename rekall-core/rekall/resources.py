#!/usr/bin/env python

# Rekall
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
# Copyright 2013 Google Inc. All Rights Reserved.
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

__author__ = "Michael Cohen <scudette@gmail.com>"
"""Finds resources which are normally bundled with Rekall.

Rekall is shipped both as a python package and as a pyinstaller
application. This module is the interface between the two.
"""

import os
import sys

import pkg_resources


def get_resource(filename, package="rekall-core", prefix="resources"):
    """Use the pkg_resources API to extract resources.

    This will extract into a temporary file in case the egg is compressed.

    Args:
      package: name of the package (e.g. rekall-core, rekall-gui).
      filename: The filename inside the package.
      prefix: The sub-directory in the source distribution which contains the
          resource.

   Returns:
      A path to the actual filename.

    """
    target = _get_pkg_resource(filename, package, prefix)
    if target and os.access(target, os.R_OK):
        return target

    # Installing from wheel places data_files relative to sys.prefix and not
    # site-packages. If we can not find in site-packages, check sys.prefix
    # instead.
    # http://python-packaging-user-guide.readthedocs.org/en/latest/distributing/#data-files
    target = os.path.join(sys.prefix, prefix, filename)
    if target and os.access(target, os.R_OK):
        return target

    raise IOError("Unable to find resource %s" % filename)


def _get_pkg_resource(filename, package, prefix):
    """Query pkg_resources for the location of the filename."""
    requirement = pkg_resources.Requirement.parse(package)
    target = os.path.join(prefix, filename)
    try:
        return pkg_resources.resource_filename(requirement, target)
    except pkg_resources.DistributionNotFound:
        # It may be that the working set is not in sync (e.g. if sys.path was
        # manipulated). Try to reload it just in case.
        pkg_resources.working_set = pkg_resources.WorkingSet()
        try:
            return pkg_resources.resource_filename(requirement, target)
        except pkg_resources.DistributionNotFound:
            return None
