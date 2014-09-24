(function() {
  var module = angular.module('manuskript.pythoncall.controller',
                              ['manuskript.core',
                               'manuskript.pythoncall.renderer.service']);

  module.controller("PythonCallController", function(
      $scope,
      manuskriptPythonCallRendererService) {

    /**
     * Joins given array of lines with '\n'.
     * @param {string[]} lines - Lines to join.
     * @returns {string} String of all the lines joined by '\n'.
     */
    $scope.joinLines = function(lines) {
      if (lines) {
        return lines.join("\n");
      } else {
        return "";
      }
    };

    /**
     * Pushes current node's sources to the server using
     * manuskriptPythonCallRendererService. Asynchronously waits for the
     * response.
     */
    $scope.pushSources = function() {
      manuskriptPythonCallRendererService.Render(
	  $scope.node.source,
          '/controllers/pythoncall',
	  function(data) {
	    $scope.node.rendered = angular.fromJson(data)["data"];
            $scope.showNode($scope.node);
	  },
	  function() {
	  });
    };

    /**
     * If node state changes to 'render', we push the sources to the server.
     */
    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.pushSources();
      }
    });

    $scope.minimizeToggle = function($event) {
      var output = $($event.target).parents(".pythoncall").first().find(".python-output");
      output.toggleClass('infinite-scroll');
    };

  });

})();
