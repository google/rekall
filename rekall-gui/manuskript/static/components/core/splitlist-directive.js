(function() {

  var module = angular.module('manuskript.core.splitList.directive', []);

  /**
   * 'splitList' directive is designed to be used together with 'ngModel'
   * directive in cases when ngModel expects a string, but we have an
   * array. 'splitList' transparently joins array elements with '\n' or,
   * alternatively, splits given string by '\n'.
   */
  module.directive('splitList', function() {
    return {
      restrict: 'A',
      priority: 10,
      require: 'ngModel',
      link: function(scope, element, attrs, ngModel) {
        var fromUser = function(text) {
          return text.split('\n');
        };

        var toUser = function(list) {
          return list.join('\n');
        };

        ngModel.$parsers.push(fromUser);
        ngModel.$formatters.push(toUser);
      }
    };
  });

})();