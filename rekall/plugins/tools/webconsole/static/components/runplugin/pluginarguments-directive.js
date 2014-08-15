'use strict';
(function() {

  var module = angular.module('rekall.runplugin.pluginArguments.directive', []);

  module.directive('rekallPluginArguments', function() {
    return {
      restrict: 'EA',
      templateUrl: '/rekall-webconsole/components/runplugin/pluginarguments.html',
      scope: {
        arguments: '=',
        filledArguments: '='
      }
    };
  });
})();