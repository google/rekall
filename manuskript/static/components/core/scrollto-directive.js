(function() {

  var module = angular.module('manuskript.core.scrollTo.directive', []);

  /**
   * 'scrollTo' directive scrolls container to a child with a corresponding
   * selector.
   */
  module.directive('scrollTo', function($timeout) {
    return {
      restrict: 'A',
      link: function(scope, element, attrs) {
	$timeout(function() {
	  var scrollAnchors = element.find(attrs["scrollTo"]);
	  if (scrollAnchors.length > 0) {
	    element.scrollTop(Math.max(0, scrollAnchors.position().top - 20));
	  }
	});
      }
    };
  });

})();