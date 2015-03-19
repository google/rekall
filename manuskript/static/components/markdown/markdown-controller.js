(function() {
  var module = angular.module('manuskript.markdown.controller', [
    'manuskript.core',
    'manuskript.core.autoFocus.directive',
  ]);

  module.controller("MarkdownController", function($scope, $sce) {

    $scope.editorOptions = {
      mode: 'markdown',
      viewportMargin: Infinity,
      onLoad: function(cm) {
        $(cm).focus();
      }
    };

    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.node.rendered = markdown.toHTML($scope.node.source.join("\n"));
        $scope.trustedHTMLString = $sce.trustAsHtml($scope.node.rendered);
        $scope.showNode($scope.node);
      }
    });
  });

})();
