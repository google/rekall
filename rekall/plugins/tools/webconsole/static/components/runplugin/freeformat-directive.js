'use strict';
(function() {

  var module = angular.module('rekall.runplugin.freeFormat.directive',
                              []);

  module.directive('rekallFreeFormat', function(
    $compile, rekallObjectActionsService) {
    return {
      restrict: 'E',
      scope: {
        element: '=',
        minimized: '='
      },

      // Render a complex format expression. For example: "Process
      // {0}".format(eprocess).
      link: function(scope, element, attrs) {
        var format = scope.element.data[0];

        // Just convert to an angular template.
        format = format.replace(
            /\{(\d+)(?:\:.+?\}|\})/g, function(match, argPos, offset) {
              return '<rekall-object object="element.data[' + (
                parseInt(argPos) + 1) + ']"></rekall-object>'
            });

        format = format.replace(/[\r\n]/g, "<br>");

        element.html(format);
        $compile(element.contents())(scope);
      }
    };
  });
})();
