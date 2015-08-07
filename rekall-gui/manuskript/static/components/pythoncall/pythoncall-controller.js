(function() {
  var module = angular.module('manuskript.pythoncall.controller',
                              ['manuskript.core',
                               'manuskript.pythoncall.renderer.service']);

  module.controller("PythonCallController", function(
      $scope, $http,
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
        {
          source: $scope.node.source,
          cell_id: $scope.node.id
        },
        '/controllers/pythoncall',
	function(data) {
	  $scope.node.rendered = angular.fromJson(data);
          $scope.showNode($scope.node);
	},
	function() {
          $http.get("worksheet/" + $scope.node.id + ".json").success(
            function(data) {
	      $scope.node.rendered = angular.fromJson(data);
              $scope.showNode($scope.node);
            });
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
