(function() {
  var module = angular.module('manuskript.shell.controller', [
    'manuskript.core',
    'manuskript.pythoncall.renderer.service'
  ]);

  module.controller("ShellController", function(
      $scope, $http,
      manuskriptPythonCallRendererService) {

    /**
     * Pushes current node's sources to the server using
     * manuskriptPythonCallRendererService. Asynchronously waits for the
     * response.
     */
    $scope.pushSources = function(node) {
      $http.post('controllers/shell', {
        cell_id: node.id,
	source: angular.copy($scope.node.source),
      }).success(function(data) {
        $scope.node.rendered = angular.fromJson(data);
        $scope.showNode($scope.node);
      });
    };

    /**
     * If node state changes to 'render', we push the sources to the server.
     */
    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.pushSources($scope.node);
      }
    });

    $scope.minimizeToggle = function($event) {
      var output = $($event.target).parents(".shell").first().find(
        ".shell-output");
      output.toggleClass('infinite-scroll');
    };

  });

})();
