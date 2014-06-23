(function() {

  var module = angular.module('manuskript.core.fastRepeat.directive', []);

  module.directive('fastRepeat', function ($parse) {
    return {
      restrict: "A",
      transclude: 'element',
      compile: function(element, attrs, linker) {
	return function($scope, $element, $attr) {
	  var match = $attr.fastRepeat.match(/^\s*(.+)\s+in\s+(.*?)\s*(\s+track\s+by\s+(.+)\s*)?$/);
	  var indexString = match[1];
	  var collectionString = match[2];

	  var collection = $scope.$eval(collectionString);
	  var parent = $element.parent();

	  for (var i = 0; i < collection.length; ++i) {
	    var childScope = $scope.$new();
	    childScope[indexString] = collection[i];
	    childScope["$index"] = i;
	    linker(childScope, function(clone) {
	      parent.append(clone);
	    });
	    childScope.$destroy();
	  }
	};
      }
    };
  });
})();