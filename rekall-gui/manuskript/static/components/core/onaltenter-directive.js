(function() {

  var module = angular.module('manuskript.core.onAltEnter.directive', []);


  /**
   * focusOn directive gives focus when a scope parameter becomes true.
   */
  module.directive('focusOn', function($timeout, $parse) {
    return {
      link: {
        post: function(scope, element, attrs) {
          var model = $parse(attrs.focusOn);

          scope.$watch(model, function(value) {
            if(value === true) {
              element[0].focus();
            }
          });

          element.bind('blur', function() {
            scope.$apply(model.assign(scope, false));
          });
        }
      }
    };
  });

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