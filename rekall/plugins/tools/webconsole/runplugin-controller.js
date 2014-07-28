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

    $scope.renderers = {
      "Literal": function(item) { return item.value; },
      "Struct": function(item) {
        if (item.value !== undefined) {
          return item.value.toString();
        } else {
          return $scope.addrpad(item.offset);
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
      },

      "Enumeration": function(item) {
        return item.enum + " (" + item.value + ")";
      },

      "_EPROCESS": function(item) {
        return item.Cybox.Name + " (" + item.Cybox.PID + ")";
      },

      "TreeNode": function(item) {
        return ($scope.repeat("* ", item.depth) +
                $scope.renderItem(item.child, {}));
      },

      /* Default fallback for unknown objects. */
      "object": function(item) {
        return "";
      }
    }

    $scope.repeat = function(item, number) {
      return new Array(number + 1).join(item);
    },

    $scope.addrpad = function(item) {
        var result = item.toString(16);
        result = $scope.repeat("0", 14 - result.length) + result;

        return "0x" + result;
    },

    $scope.renderItem = function(item, header) {
      var renderer = null;

      if (item == null) {
        return "-";
      }

      /* A literal string which converted to a utf8 unicode string. */
      if (item.length == 2 && item[0] == "*") {
        return item[1];
      }

      if (!isNaN(parseInt(item)) &&
          header.formatstring == "[addrpad]" || header.addrpad) {
        return $scope.addrpad(item);
      }

      renderer = $scope.renderers[item.type_name];
      if (renderer) {
        return renderer(item);
      }

      /* Check the item's mro for specialized renderers. */
      if (item.mro) {
        for (var i = 0; i < item.mro.length; ++i) {
          renderer = $scope.renderers[item.mro[i]];
          if (renderer !== undefined) {
            return renderer(item);
          }
        }
      }

      /* If we do not have specialized renderers, just return the item as is. */
      return item;
    };

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
        $scope.requiredArguments = $filter('filter')(
            $scope.node.source.plugin.arguments, {required: true });
        $scope.optionalArguments = $filter('filter')(
            $scope.node.source.plugin.arguments, {required: false });
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
              $scope.node.rendered = angular.fromJson(data);

              var json_output = $scope.node.rendered.json_output
              var state = rekallJsonRendererService.createEmptyState();
              if (json_output != null) {
                rekallJsonRendererService.parse(json_output, state);
              }

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