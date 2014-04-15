(function() {

  var module = angular.module('manuskript.core.onAltEnter.directive', []);

  /**
   * 'onAltEnter' directive executed 'onAltEnter' handler when either
   * Command+Enter or Control+Enter is pressed.
   */
  module.directive('onAltEnter', function() {
    return function(scope, element, attrs) {
      element.keydown(function(event) {
        if (event.which == 13 && (event.ctrlKey || event.metaKey)) {
	  scope.$evalAsync(attrs.onAltEnter);
        }
      });
    };
  });

})();