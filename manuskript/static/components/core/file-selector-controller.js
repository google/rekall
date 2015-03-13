(function() {

  var module = angular.module('manuskript.core.fileSelector.controller',
                              ['manuskript.core']);

  module.controller("FileSelectorController", function($scope, $http) {
    $scope.files = [];

    $scope.updatePath = function(file) {
      $scope.error = null;

      if (file.type == "directory") {
        $scope.filename += file.name + "/";
        return;
      };

      // Tell the server to switch worksheet files, and if successful reload the
      // entire interface.
      $http.get(
        location.href + 'worksheet/load_file', {
          params: {
            path: $scope.filename + file.name,
          }
        }).success(function(response) {
          location.reload();
        }).error(function(response) {
          $scope.error = response;
        });;

    };

    $scope.previousDir = function() {
      var components = $scope.filename.split("/");
      if (components.length > 2) {
        components.splice(components.length - 2, 2);
        $scope.filename = components.join("/") + "/";
      };
    };

    $scope.saveWorksheet = function(filename) {
      // Tell the server to switch worksheet files, and if successful reload the
      // entire interface.
      $http.get(
        location.href + 'worksheet/save_file', {
          params: {
            path: $scope.filename + filename,
          }
        }).success(function(response) {
          location.reload();
        }).error(function(response) {
          $scope.error = response;
        });;
    };

    $scope.$watch("filename", function() {
      $scope.error = null;

      $http.get(
        location.href + 'worksheet/list_files', {
          params: {
            path: $scope.filename,
          }
        }).success(function(response){
          $scope.files = response.files;
        }).error(function (response) {
          $scope.error = response;
        });
    });
  });
})();
