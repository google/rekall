import inspect

from rekall import config
from rekall import ipython_support

# Load all the plugins to register them.
from rekall import plugins  # pylint: disable=unused-import
from rekall import utils
from rekall import session

IPython = utils.ConditionalImport("IPython")


def ImportEnvironment(**kwargs):
    """Initialize a caller's environment.

    Creates a new interactive environment and installs it into the caller's
    local namespace. After this call the usual rekall interactive environment
    will be added in the caller's local namespace.

    For example:

    from rekall import interactive

    interactive.ImportEnvironment()

    # Update the filename, load profile etc.
    session.filename = "xpimage.dd"

    # Run the pslist command rendering to stdout.
    print pslist()
    """
    s = session.InteractiveSession(**kwargs)
    with s.state as state:
        config.MergeConfigOptions(state)

    stack = inspect.stack()
    # pylint: disable=protected-access
    s._locals = stack[1][0].f_locals
    s._prepare_local_namespace()


    # For IPython fix up the completion.
    try:
        shell = IPython.get_ipython()
        shell.Completer.matchers.insert(
            0, lambda x: ipython_support.RekallCompleter(shell.Completer, x))

        shell.Completer.merge_completions = False
    except Exception, e:
        print e
