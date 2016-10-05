# This module provides for a central knowledge base which plugins can use to
# collect information.

from rekall import plugin
from rekall import registry


class ParameterHook(plugin.ModeBasedActiveMixin):
    """A mechanism for automatically calculating a parameter.

    The session contains many parameters which are calculated through the
    various plugins, or provided by the user. These parameters essentially
    represent a growing body of knowledge about the image we are currently
    analysing.

    Some plugins require this information before they can continue. If the
    information is already known, we do not need to re-derive it, and the value
    can be cached in the session.

    A ParameterHook is a class which is called to find out the value of a
    parameter when it is not known.
    """
    __abstract = True

    __metaclass__ = registry.MetaclassRegistry

    # The name of the parameter we will be calculating. This class will
    # automatically be called when someone accessed this name, and it is not
    # already known.
    name = None

    # The number of seconds this parameter can be assumed valid - or None if the
    # parameter does not expire. NOTE that expiry is only considered in the
    # physical_address_space.metadata("live") == True.
    expiry = None

    # Signifies if this parameter is considered volatile (i.e. is likely to
    # change on a live system).
    volatile = True

    def __init__(self, session):
        if session == None:
            raise RuntimeError("Session must be set")

        self.session = session

    def calculate(self):
        """Derive the value of the parameter."""
