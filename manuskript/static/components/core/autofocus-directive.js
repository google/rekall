(function() {
  var module = angular.module('manuskript.core.autoFocus.directive', []);

  module.directive('autoFocus', function($timeout) {
    return {
      restrict: 'AC',
      link: function(_scope, _element) {
        $timeout(function(){
          _element[0].focus();
        }, 0);
      }
    };
  });

})();
