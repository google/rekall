(function() {
  var module = angular.module('rekall.runplugin.controller',
                              ['manuskript.core',
                               'manuskript.pythoncall.renderer.service',
                               'rekall.runplugin.jsonRenderer.service',
                               'rekall.runplugin.pluginArguments.directive',
                               'ui.bootstrap',
                               'pasvaz.bindonce']);

  module.controller("RekallRunPluginController", function($scope, $filter,
                                                          rekallPluginRegistryService,
                                                          rekallJsonRendererService,
                                                          manuskriptPythonCallRendererService) {

    $scope.knownValueTypes = ["Literal",
                              "Struct",
                              "NativeType",
                              "Pointer",
                              "AddressSpace",
                              "NoneObject",
                              "DateTime"];
    $scope.renderers = {
      "Literal": function(item) { return item.value; },
      "Struct": function(item) {
        if (item.value !== undefined) {
          return item.value.toString();
        } else {
          return item.offset;
        }
      },
      "NativeType": function(item) { return item.value; },
      "Pointer": function(item) { return item.value; },
      "AddressSpace": function(item) { return item.name; },
      "NoneObject": function(item) { return "-"; },
      "UnixTimeStamp": function(item) {
        if (!item.epoch) {
          return "-";
        } else {
          return $filter("date")(item.epoch * 1000, "medium");
        }
      }
    }

    $scope.renderItem = function(item, header) {
      /* Check if we can guess how to output the value by looking into
       * format string */
      var format_string = header[2];
      var value = null;

      if (format_string[0] == "!") {
        format_string = format_string.substr(1);
      }

      if (format_string == "[addrpad]") {
        format_string = "{:#014x}";
        value = item.offset;
        if (value === undefined) {
          value = item;
        }
      } else if (format_string == "[addr]") {
        format_string = "{:>#14x}";
        value = item.offset;
        if (value === undefined) {
          value = item;
        }
      }

      if (value !== null) {
        value = format(format_string, value);
        return value;
      }

      /* If the object has no type, we don't know how to render it at this
       * point */
      if (!(item instanceof Object)) {
        if (item === undefined || item === null) {
          return "";
        } else {
          return item.toString();
        }
      }

      /* Find appropriate renderer by inspecting types chain. */
      var types = item.type.split(",");
      for (var i = 0; i < types.length; ++i) {
        var renderer = $scope.renderers[types[i]];
        if (renderer !== undefined) {
          break;
        }
      }

      if (renderer !== undefined) {
        return renderer(item);
      } else {
        if (item.value) {
          return item.value.toString();
        } else {
          return "";
        }
      }
    }

    $scope.search = {
      pluginName: ""
    };

    $scope.plugins = [];

    rekallPluginRegistryService.getPlugins(function(result) {
      $scope.plugins = result;

      $scope.pluginsValues = [];
      for (var key in $scope.plugins) {
        $scope.pluginsValues.push($scope.plugins[key]);
      }
    });

    $scope.firstLineOnly = function(str) {
      if (str) {
        return str.split("\n")[0];
      } else {
        return str;
      }
    };

    $scope.$watch("node.source.plugin", function() {
      if ($scope.node.source.plugin) {
        $scope.requiredArguments = $filter('filter')($scope.node.source.plugin.arguments, {required: true });
        $scope.optionalArguments = $filter('filter')($scope.node.source.plugin.arguments, {required: false });
      }
    });

    $scope.templateForColumn = function(column) {
      if (column.type !== undefined) {
        semanticType = column.type;
      } else {
        semanticType = "Default";
      }
      return rekallJsonRendererService.cellTemplateForSemanticType(semanticType);
    }

    $scope.pushSources = function() {
      if ($scope.node.source.plugin) {
        var sourceString = $scope.node.source.plugin.name + "()";
        manuskriptPythonCallRendererService.Render(
            $scope.node.source,
            '/rekall/runplugin',
            function(data) {
              $scope.node.rendered = angular.fromJson(data)["data"];

              var json_output = JSON.parse($scope.node.rendered.json_output)
              var state = rekallJsonRendererService.createEmptyState();
              rekallJsonRendererService.parse(json_output, state);

	      // Uncomment to see what rekall plugin's output gets rendered.
              // console.log(["PLUGIN_OUTPUT", state]);
              $scope.node.rendered['plugin_output'] = state;

              $scope.node.state = 'show';
            },
            function() {
            });
      } else {
        $scope.node.rendered = {
          stderr: ['No Rekall plugin was selected.'],
          stdout: [],
          error: []
        };
        $scope.node.state = 'show';
      }
    };

    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.pushSources();
      }
    });

  });

})();