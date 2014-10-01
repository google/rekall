'use strict';
(function() {

  var module = angular.module('rekall.runplugin.pluginArguments.directive',
                              ['manuskript.core.network.service']);

  // An ng-model directive to convert to/from HEX.
  module.directive('rekallInt', function() {
    return {
      require: 'ngModel',

      link: function(scope, elem, attr, ngModel) {

        ngModel.$parsers.unshift(function(value) {
          if (value === "") {
            ngModel.$setValidity('rekallInt', true);
            return result;
          };

          if (value.match(/^(0x[0-9a-fA-F]+|[0-9]*)$/)) {
            var result = parseInt(value);
            if ($.isNumeric(result)) {
              ngModel.$setValidity('rekallInt', true);
              return result;
            }
          };

          ngModel.$setValidity('rekallInt', false);
          return value;
        });

        ngModel.$formatters.unshift(function(value) {
          if (value > 0x1000) {
            return "0x" + value.toString(16);
          } else {
            return value;
          }
        });
      }
    }
  });

  // An ng-model directive to convert to/from HEX arrays.
  module.directive('rekallIntArray', function() {
    return {
      require: 'ngModel',

      link: function(scope, elem, attr, ngModel) {

        ngModel.$parsers.unshift(function(value) {
          if (value === "") {
            ngModel.$setValidity('rekallIntArray', true);
            return result;
          };

          var splitted = value.split(",");
          var resultArray = [];
          var error = false;

          for (var i=0; i<splitted.length; i++) {
            if (splitted[i].match(/^ *(0x[0-9a-fA-F]+|[0-9]+) *$/)) {
              var result = parseInt(splitted[i]);

              if ($.isNumeric(result)) {
                resultArray.push(result);
                continue;
              };
            }
            ngModel.$setValidity('rekallIntArray', false);
            return value;
          };

          ngModel.$setValidity('rekallIntArray', true);
          return resultArray;
        });

        ngModel.$formatters.unshift(function(value) {
          var result = [];
          if (angular.isArray(value)) {
            for (var i=0; i<value.length; i++) {
              if (value[i] > 0x1000) {
                result.push("0x" + value[i].toString(16));
              } else {
                result.push(value[i]);
              }
            };
          };

          return result.join();
        });
      }
    }
  });

  module.directive('rekallPluginArguments', function($http) {
    return {
      restrict: 'EA',
      templateUrl: '/rekall-webconsole/components/runplugin/pluginarguments.html',
      scope: {
        arguments: '=',
        filledArguments: '='
      },

      link: function(scope, elem, attr) {
        scope.getSymbols = function(value) {
          return $http.get(location.href + 'rekall/symbol_search', {
            params: {
              symbol: value,
            }
          }).then(function(response){
            return response.data.results;
          });
        };

        // Prefill the defaults.
        for (var i=0; i<scope.arguments.length; i++) {
          var arg = scope.arguments[i];
          var existing_value = scope.filledArguments[arg.name];

          if (existing_value === null && arg.default !== null) {
            scope.filledArguments[arg.name] = arg.default;
          };
        }
      }
    };
  });
})();