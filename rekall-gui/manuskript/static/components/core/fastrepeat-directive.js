(function() {

  var module = angular.module('manuskript.core.fastRepeat.directive', []);

  module.directive('fastRepeat', function() {
    return {
      restrict: "A",
      transclude: 'element',
      compile: function(element, attrs, linker) {
        return function($scope, $element, $attr) {
          var match = $attr.fastRepeat.match(/^\s*(.+)\s+in\s+(.*?)\s*(\s+track\s+by\s+(.+)\s*)?$/);
          var noWatch = $attr.noWatch !== undefined;
          var preserveScope = $attr.preserveScope !== undefined;
          var indexString = match[1];
          var collectionString = match[2];

          var parent = $element.parent();

          var state = {
            index: 0
          };
          var watchHandler = function(newValue, oldValue) {
            var collection = $scope.$eval(collectionString);
            var scopes = [];
            if (collection == null)
              return;

            for (var i = state.index; i < collection.length; ++i) {
              var childScope = $scope.$new();
              childScope[indexString] = collection[i];
              childScope["$index"] = i;
              linker(childScope, function(clone) {
                parent.append(clone);
              });

              if (!preserveScope) {
                scopes.push(childScope);
              }
            }
            $scope.$evalAsync(function() {
              for (var i = 0; i < scopes.length; ++i) {
                scopes[i].$destroy();
              }
            });

            state.index = collection.length;
          }

          if (noWatch) {
            var collection = $scope.$eval(collectionString);
            watchHandler(collection.length, 0);
          } else {
            $scope.$watch(collectionString + ".length", function(newValue, oldValue) {
              watchHandler(newValue, oldValue);
            });
          }

        };
      }
    };
  });
})();