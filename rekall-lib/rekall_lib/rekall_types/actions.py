from rekall_lib.rekall_types import collections
from rekall_lib import serializer


class Action(serializer.SerializedObject):
    """An action is run on the client."""
    """Requests a client action to run on the agent.

    Action implementations will extend this message.
    """

    schema = [
        dict(name="condition",
             doc="An Efilter condition to evaluate before running."),
        dict(name="rekall_session", type="dict",
             doc="The session that will be invoked for this flow."),
    ]

    def is_active(self):
        """Returns true if this action is active.

        The condition is evaluated.
        """
        if self.condition:
            if not list(self._session.plugins.search(self.condition)):
                return False

        return True

    def run(self, flow_obj=None):
        """Called by the client to execute this action.

        Returns a list of collections that have been written by this action.
        """
        raise NotImplementedError()


class CollectAction(Action):
    """Collect the results of an efilter query into a collection."""

    schema = [
        dict(name="query", type="dict",
             doc="The dotty/EFILTER query to run."),

        dict(name="query_parameters", type="dict",
             doc="Optional parameters for parametrized queries."),

        dict(name="collection", type=collections.CollectionSpec,
             doc="A specification for constructing the output collection."),
    ]


class PluginAction(Action):
    """Run the plugin and writes the output to a collection."""

    schema = [
        dict(name="plugin"),

        dict(name="args", type="dict",
             doc="Parameters for plugin."),

        dict(name="collection", type=collections.CollectionSpec,
             doc="A specification for constructing the output collection."
             " Note that tables will be added automatically."),
    ]
