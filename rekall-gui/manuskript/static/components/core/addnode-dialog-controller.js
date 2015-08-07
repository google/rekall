(function() {
  var module = angular.module('manuskript.core.addNodeDialog.controller',
                              ['ui.bootstrap',
                               'cfp.hotkeys']);

  module.controller("AddNodeDialogController", function(
    $scope, $modalInstance, hotkeys, items) {

    $scope.items = items;

    $scope.ok = function(selectedItem) {
      $modalInstance.close(selectedItem);
    };
  });

})();