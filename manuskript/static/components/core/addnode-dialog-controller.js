(function() {
  var module = angular.module('manuskript.core.addNodeDialog.controller', ['ui.bootstrap']);

  module.controller("AddNodeDialogController", function($scope, $modalInstance, items) {

    $scope.items = items;

    $scope.ok = function(selectedItem) {
      $modalInstance.close(selectedItem);
    };

  });

})();