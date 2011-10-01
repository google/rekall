# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

"""
@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@gmail.com

"""

from volatility import registry

## Make sure the profiles are cached so we only parse it once.
PROFILES = {}


class Error(Exception):
    """A generic profile error."""


def Profile(config):
    """A factory for profiles."""
    profile_name = config.PROFILE
    if not profile_name:
        raise Error("Profile not specified.")

    try:
        ret = PROFILES[profile_name]
    except KeyError:
        try:
            ret = registry.PROFILES[profile_name](config)
            PROFILES[profile_name] = ret
        except KeyError:
            raise Error("Invalid profile %s" % profile_name)

    return ret


def get_profile_class(config):
    """Returns the profile class without instantiating it."""
    profile_name = config.PROFILE
    if not profile_name:
        raise Error("Profile not specified.")

    try:
        return registry.PROFILES[profile_name]
    except KeyError:
        raise Error("Invalid profile %s" % profile_name)
