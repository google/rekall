import json
from manuskript import plugin

from manuskript.plugins.plaintext import PlainText
from manuskript.plugins.markdown import Markdown
from manuskript.plugins.pythoncall import PythonCall
from manuskript.plugins.shell import Shell


class AppDeps(plugin.Plugin):
    """A Psuedo plugin to define the main app's requirements."""

    JS_FILES = [
        "static/bower_components/jquery/dist/jquery.js",
        "static/bower_components/file-saver/FileSaver.js",
        "static/bower_components/ng-file-upload/angular-file-upload-shim.js",
        "static/bower_components/angular/angular.js",
        "static/bower_components/bootstrap/dist/js/bootstrap.js",
        "static/bower_components/markdown/lib/markdown.js",
        "static/bower_components/codemirror/lib/codemirror.js",
        "static/bower_components/codemirror/mode/python/python.js",
        "static/bower_components/codemirror/mode/markdown/markdown.js",
        "static/bower_components/codemirror/mode/xml/xml.js",
        "static/bower_components/angular-resource/angular-resource.js",
        "static/bower_components/angular-animate/angular-animate.js",
        "static/bower_components/angular-bootstrap/ui-bootstrap-tpls.js",
        "static/bower_components/ng-file-upload/angular-file-upload.js",
        "static/bower_components/angular-hotkeys/build/hotkeys.min.js",

        # internal dependencies
        "static/components/core/addnode-dialog-controller.js",
        "static/components/core/codeeditor-directive.js",
        "static/components/core/core.js",
        "static/components/core/fastrepeat-directive.js",
        "static/components/core/fileinput-directive.js",
        "static/components/core/file-selector-controller.js",
        "static/components/core/network-service.js",
        "static/components/core/nodepluginregistry-service.js",
        "static/components/core/onaltenter-directive.js",
        "static/components/core/scrollto-directive.js",
        "static/components/core/autofocus-directive.js",
        "static/components/core/splitlist-directive.js",

    ]

    CSS_FILES = [
        "static/bower_components/bootstrap/dist/css/bootstrap.css",
        "static/bower_components/codemirror/lib/codemirror.css",
        "static/bower_components/angular-hotkeys/build/hotkeys.min.css",

        # Internal stylesheets.
        "static/index.css",
    ]


class MainApp(plugin.Plugin):
    JS_FILES = [
        "static/load-controller.js",
        "static/app-controller.js",
        "static/app.js",
    ]

    CONFIG = {}

    @classmethod
    def GenerateHTML(cls, root_url="/"):
        data = super(MainApp, cls).GenerateHTML(root_url=root_url)
        data += """
        <script>
        $('html').data(%s);
        </script>
        """ % json.dumps(cls.CONFIG)

        return data
