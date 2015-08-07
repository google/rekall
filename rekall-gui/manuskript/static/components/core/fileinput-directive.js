(function() {

  var module = angular.module('manuskript.core.fileInput.directive', []);

  /**
   * 'fileInput' directive creates an <input type='file' ...> element and binds
   * the selected file using '=file' binding.
   */
  module.directive('fileInput', function ($parse) {
    return {
      restrict: "EA",
      template: "<input type='file' />",
      replace: true,
      scope: {
        file: '='
      },
      link: function(scope, el, attrs){
        el.bind('change', function(event){
          var files = event.target.files;
          var file = files[0];
          scope.file = file ? file : undefined;
          scope.$apply();
        });
      }
    };
  });
})();