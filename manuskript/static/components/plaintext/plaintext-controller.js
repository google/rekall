(function() {
  var module = angular.module('manuskript.plaintext.controller',
                              ['manuskript.core']);

  module.controller("PlainTextController", function($scope) {

    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.node.rendered = $scope.node.source.slice();
        $scope.showNode($scope.node);
      }
    });
  });

})();