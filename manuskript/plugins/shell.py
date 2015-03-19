import hashlib
import json
import logging

from flask import jsonify
from flask import request

from manuskript import plugin
from manuskript import shell


def GenerateCacheKey(state):
    data = json.dumps(state, sort_keys=True)
    hash = hashlib.md5(data).hexdigest()
    try:
        return "%s-shell" % (hash)
    except KeyError:
        return hash


class Shell(plugin.Plugin):
    ANGULAR_MODULE = "manuskript.shell"

    JS_FILES = ["/static/components/pythoncall/renderer-service.js",
                "/static/components/shell/shell-controller.js",
                "/static/components/shell/shell.js"]

    CSS_FILES = ["/static/components/shell/shell.css"]

    @classmethod
    def PlugIntoApp(cls, app):

        @app.route("/controllers/shell", methods=["POST"])
        def shell_call():  # pylint: disable=unused-variable
            if cls.__name__ not in app.config:
                app.config[cls.__name__] = shell_ = shell.Shell()

            shell_ = app.config[cls.__name__]
            cell = request.get_json()
            cell_id = cell["cell_id"]
            source_code = cell["source"]
            worksheet = app.config["worksheet"]

            # If the data is cached locally just return it.
            cache_key = "%s/%s" % (cell_id, GenerateCacheKey(source_code))
            cache_filename = "%s/shell" % cell_id

            cache = worksheet.GetData(cache_filename)
            if cache and cache["cache_key"] == cache_key:
                logging.debug("Dumping request from cache")
                return json.dumps(cache)

            result = None
            error = None
            is_parsing_error = False

            try:
                stdout, stderr, result = shell_.Exec(
                    source_code, cwd=worksheet.location)
            except shell.ParseError as e:
                stdout, stderr, error = "", "", e.original_error
                is_parsing_error = True
            except shell.ExecError as e:
                stdout, stderr, error = e.stdout, e.stderr, e.original_error

            result = dict(stdout=stdout,
                          stderr=stderr,
                          result=result,
                          error=error,
                          cache_key=cache_key)

            response = jsonify(result)

            # Cache the data in the worksheet.
            worksheet.StoreData(cache_filename, result)

            return response
