'use strict';
(function() {
  var module = angular.module('rekall.fileupload.controller', [
    'manuskript.core',
  ]);

  module.controller("FileUploadController", function(
    $scope, $upload) {
    if ($scope.node.rendered == null) {
      $scope.node.rendered = [];
    };

    $scope.$watch('node.state', function() {
      if ($scope.node.state == 'render') {
        $scope.node.rendered.caption = $scope.node.source.caption;
        $scope.showNode($scope.node);
      };
    });

    $scope.minimizeToggle = function(event) {
      var size = $scope.node.source.size;
      $scope.node.source.size = (size + 1) % 3;
    };

    $scope.select = function(index) {
      if ($scope.selected == index) {
        $scope.selected = null;
      } else {
        $scope.selected = index;
      }
    };

    // Remove the filename from the embedded files.
    $scope.removeFile = function() {
      $scope.node.source.files.splice($scope.selected, 1);
      $scope.selected = null;
      $scope.renderNode($scope.node);
    };

    $scope.onFileSelect = function($files) {
      for (var i = 0; i < $files.length; i++) {
        var file = $files[i];

        $scope.upload = $upload.upload({
          url: 'rekall/upload/' + $scope.node.id,
          data: {
            type: file.type
          },
          file: file,
        }).success(function(data, status, headers, config) {
          for (var i=0; i < $scope.node.source.files.length; i++ ) {
            if (file.name == $scope.node.source.files[i].name) {
              return;
            }
          };

          $scope.node.source.files.push({
            name: file.name,
            type: file.type});

          // Sources are updated, Render the node with the new data.
          $scope.renderNode($scope.node);
        });
      }
    };
  });

})();
