'use strict';
(function() {
  var module = angular.module('rekall.runplugin.controller',
                              ['manuskript.core',
			       'rekall.runplugin.contextMenu.directive',
			       'rekall.runplugin.freeFormat.directive',
                               'rekall.runplugin.jsonDecoder.service',
                               'rekall.runplugin.objectActions.init',
                               'rekall.runplugin.objectActions.service',
                               'rekall.runplugin.objectRenderer.service',
                               'rekall.runplugin.pluginArguments.directive',
			       'rekall.runplugin.pluginRegistry.service',
			       'rekall.runplugin.tableCell.directive',
                               'ui.bootstrap',
                               'pasvaz.bindonce']);

  module.controller('RekallRunPluginController', function($scope, $filter,
                                                          rekallPluginRegistryService,
                                                          rekallJsonDecoderService) {

    $scope.search = {
      pluginName: ''
    };

    $scope.plugins = [];

    rekallPluginRegistryService.getPlugins(function(result) {
      $scope.plugins = result;

      $scope.pluginsValues = [];
      for (var key in $scope.plugins) {
        $scope.pluginsValues.push($scope.plugins[key]);
      }
    });

    $scope.$watch('node.source.plugin', function() {
      if ($scope.node.source.plugin) {
        $scope.requiredArguments = $filter('filter')($scope.node.source.plugin.arguments, {required: true });
        $scope.optionalArguments = $filter('filter')($scope.node.source.plugin.arguments, {required: false });
      }
    });

    $scope.pushSources = function() {
      if ($scope.node.source.plugin) {
	var socket = new WebSocket('ws://' + location.host + '/rekall/runplugin');
        var state = rekallJsonDecoderService.createEmptyState();

        $scope.node.rendered['plugin_output'] = state;
        $scope.node.state = 'render';

	socket.onopen = function(msg) {  // jshint ignore:line
	  socket.send(JSON.stringify($scope.node.source));
	};
	socket.onerror = function(error) {  // jshint ignore:line
	  // TODO(mbushkov): implement proper error handling
	};
	socket.onclose = function(msg) {  // jshint ignore:line
	  $scope.node.rendered['plugin_output'] = state;
	  $scope.node.state = 'show';
	};
	var queue = [];
	socket.onmessage = function(event) {
	  var jsonOutput = JSON.parse(event.data);
	  for (var i = 0; i < jsonOutput.length; ++i) {
	    queue.push(jsonOutput[i]);
	  }
	  $scope.$evalAsync(function() {
	    if (queue.length > 0) {
              rekallJsonDecoderService.decode(queue, state);
	      queue.splice(0, queue.length);
	    }
	  });
	};

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
      if ($scope.node.state === 'render') {
        $scope.pushSources();
      }
    });

  });

})();