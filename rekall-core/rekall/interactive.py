import inspect

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
    rekal filename="xpimage.dd"

    # Run the pslist command rendering to stdout.
    print pslist()
    """
    isession = session.InteractiveSession(use_config_file=True, **kwargs)

    stack = inspect.stack()
    # pylint: disable=protected-access
    isession._locals = stack[1][0].f_locals
    isession._prepare_local_namespace()


    # For IPython fix up the completion.
    try:
        shell = IPython.get_ipython()
        if shell:
            shell.Completer.matchers.insert(
                0,
                lambda x: ipython_support.RekallCompleter(shell.Completer, x))

            shell.Completer.merge_completions = False
    except Exception as e:
        print(e)

    return isession
