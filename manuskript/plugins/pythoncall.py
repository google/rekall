
import hashlib
import json
import logging

from flask import jsonify
from flask import request

from manuskript import plugin
from manuskript import pythonshell

def GenerateCacheKey(state):
    data = json.dumps(state, sort_keys=True)
    hash = hashlib.md5(data).hexdigest()
    try:
        return "%s-python" % (hash)
    except KeyError:
        return hash


class PythonCall(plugin.Plugin):
    ANGULAR_MODULE = "manuskript.pythoncall"

    JS_FILES = ["/static/components/pythoncall/renderer-service.js",
                "/static/components/pythoncall/pythoncall-controller.js",
                "/static/components/pythoncall/pythoncall.js"]

    CSS_FILES = ["/static/components/pythoncall/pythoncall.css"]

    @classmethod
    def UpdatePythonShell(cls, app, shell):
        pass

    @classmethod
    def PlugIntoApp(cls, app):

        @app.route("/controllers/pythoncall", methods=["POST"])
        def python_call():  # pylint: disable=unused-variable
            if cls.__name__ not in app.config:
                app.config[cls.__name__] = shell = pythonshell.PythonShell()
                cls.UpdatePythonShell(app, shell)
            shell = app.config[cls.__name__]
            cell = request.get_json()
            cell_id = cell["cell_id"]

            source_code = request.get_json()["source"]
            worksheet = app.config["worksheet"]

            # If the data is cached locally just return it.
            cache_key = "%s/%s" % (cell_id, GenerateCacheKey(source_code))
            cache_filename = "%s/python" % cell_id

            cache = worksheet.GetData(cache_filename)
            if cache and cache["cache_key"] == cache_key:
                logging.debug("Dumping request from cache")
                return json.dumps(cache)


            result = None
            error = None
            is_parsing_error = False

            try:
                stdout, stderr, result = shell.Exec("\n".join(source_code))
            except pythonshell.ParseError as e:
                stdout, stderr, error = "", "", e.original_error
                is_parsing_error = True
            except pythonshell.ExecError as e:
                stdout, stderr, error = e.stdout, e.stderr, e.original_error

            stdout_lines = stdout and stdout.split("\n") or []
            stderr_lines = stderr and stderr.split("\n") or []
            if not error:
                result_lines = result and str(result).split("\n") or []
                error_lines = []
            else:
                result_lines = []
                error_lines = str(error).split("\n")

            result = dict(stdout=stdout_lines,
                          stderr=stderr_lines,
                          result=result_lines,
                          error=error_lines,
                          cache_key=cache_key,
                          is_parsing_error=is_parsing_error,
                          execution_count=shell.execution_count)

            # Cache the data in the worksheet.
            worksheet.StoreData(cache_filename, result)

            return jsonify(result)
