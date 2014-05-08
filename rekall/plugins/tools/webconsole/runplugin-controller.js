(function() {
  var module = angular.module('rekall.runplugin.controller',
                              ['manuskript.core',
                               'manuskript.pythoncall.renderer.service',
                               'rekall.runplugin.pluginArguments.directive',
                               'ui.bootstrap']);

  module.controller("RekallRunPluginController", function($scope, $filter, rekallPluginRegistryService, manuskriptPythonCallRendererService) {

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

    $scope.pushSources = function() {
      if ($scope.node.source.plugin) {
	var sourceString = $scope.node.source.plugin.name + "()";
	manuskriptPythonCallRendererService.Render(
	    $scope.node.source,
            '/rekall/runplugin',
	    function(data) {
	      $scope.node.rendered = angular.fromJson(data)["data"];
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