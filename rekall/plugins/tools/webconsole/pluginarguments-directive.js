(function() {

  var module = angular.module('rekall.runplugin.pluginArguments.directive', []);

  module.directive('rekallPluginArguments', function() {
    return {
      restrict: "EA",
      templateUrl: "/rekall-webconsole/pluginarguments.html",
      scope: {
        arguments: '=',
        filledArguments: '='
      },
      link: function(scope, el, attrs){
      }
    };
  });
})();