# Volatility
# Copyright (C) 2011
#
# Michael Cohen <scudette@users.sourceforge.net> 
#
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# *****************************************************

#pylint: disable-msg=C0111

""" This module implements a class registry.

We scan the memory_plugins directory for all python files and add those
classes which should be registered into their own lookup tables. These
are then ordered as required. The rest of Volatility will then call onto the
registered classes when needed.

The MetaclassRegistry automatically adds any derived class to the base
class. This means that we do not need to go through a special initializating
step, as soon as a module is imported, the plugin is registered.
"""

import abc
import os
import zipfile
from volatility import constants
from volatility import debug
from volatility import conf
config = conf.ConfFactory()


class MetaclassRegistry(abc.ABCMeta):
    """Automatic Plugin Registration through metaclasses."""

    def __init__(mcs, name, bases, env_dict):
        abc.ABCMeta.__init__(mcs, name, bases, env_dict)

        # Attach the classes dict to the baseclass and have all derived classes
        # use the same one:
        for base in bases:
            try:
                mcs.classes = base.classes
                mcs.plugin_feature = base.plugin_feature
                mcs.top_level_class = base.top_level_class
                break
            except AttributeError:
                mcs.classes = {}
                mcs.plugin_feature = mcs.__name__
                # Keep a reference to the top level class
                mcs.top_level_class = mcs

        # The following should not be registered as they are abstract. Classes
        # are abstract if the have the __abstract attribute (not this is not
        # inheritable so each abstract class much be explicitely marked).
        abstract_attribute = "_%s__abstract" % name
        if getattr(mcs, abstract_attribute, None):
            return

        if not mcs.__name__.startswith("Abstract"):
            mcs.classes[mcs.__name__] = mcs

            try:
                if mcs.top_level_class.include_plugins_as_attributes:
                    setattr(mcs.top_level_class, mcs.__name__, mcs)
            except AttributeError:
                pass
