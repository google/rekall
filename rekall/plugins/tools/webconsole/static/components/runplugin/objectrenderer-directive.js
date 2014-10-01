'use strict';
(function() {

  var module = angular.module('rekall.runplugin.tableCell.directive',
                              ['rekall.runplugin.contextMenu.directive',
                               ]);

  module.directive('addrpad', function() {
    return {
      restrict: 'E',
      scope: {
        object: '=',
        pad: '=',
      },
      transclude: true,
      link: function(scope, element, attrs, contextMenuCtrl) {
        var addrValue = scope.object;
        var pad = scope.pad || 0;

        if (angular.isString(addrValue)) {
          scope.address = addrValue;
          return;
        };

        if (addrValue === undefined || addrValue === null) {
          scope.address = '-';
        } else {
          var result = addrValue.toString(16);

          if (result.length < scope.pad) {
            result = new Array(14 - result.length).join('0') + result;
          }
          scope.address = "0x" + result;
        }
      },
      template: '<samp><span bo-bind="address" /></samp>'
    }
  });

  module.directive('rekallInstruction', function ($compile) {
    return {
      restrict: 'E',
      scope: {
        object: '=',
      },
      link: function(scope, element, attrs) {
        var links = [];
        var format = scope.object.value;

        var replacement_function = function(match, argPos, offset) {
          var position = links.length;

          links.push({
            mro: ["Address"],
            value: match
          });
          return "{" + position + "}";
        }

        format = format.replace(
            /[a-z]+![a-zA-Z0-9@?]+(\s*[+]\s+0x[a-fA-F0-9]+)?/g, replacement_function);

        format = format.replace(
            /0x[0-9a-fA-F]+/g, replacement_function);

        scope.element = {data: [format].concat(links)};

        element.html("<rekall-free-format element='element'/>");
        $compile(element.contents())(scope);
      }
    };
  });


  // All the available templates - must be kept in sync with the
  // objectrenderer.html template.
  var templates = {
    'Address': true,
    'AddressSpace': true,
    'BaseObject': true,
    'Enumeration': true,
    'Instruction': true,
    'Literal': true,
    'NativeType': true,
    'NoneObject': true,
    'PaddedAddress': true,
    'Pointer': true,
    'Struct': true,
    'UnixTimeStamp': true,
    '_EPROCESS': true,
    'bool': true,
  };

  var getTemplate = function(item) {
    if (item == null) {
      return ""
    };

    // Check the item's mro for specialized renderers.
    if (!(item instanceof Object)) {
      // A large integer is assumed to be an address. This should not
      // generally happen by well behaving plugins that pass Address objects
      // to the renderer by it sometimes happens.
      if (angular.isNumber(item) && item > 10000) {
        return "LiteralAddress"

        // Bools are sent as json objects.
      } else if (jQuery.type(item) == 'boolean') {
        return 'bool';
      } else {
        return jQuery.type(item);
      };
    }

    if (item.mro != null) {
      for (var i = 0; i < item.mro.length; ++i) {
        if (templates[item.mro[i]]) {
          return item.mro[i];
        }
      }
    }
  };

  module.directive('rekallObject', function($compile, $timeout) {
    return {
      restrict: 'E',
      scope: {
        object: '=',
      },
      link: function(scope, element, attrs) {
        if (scope.object === null) {
          return;
        };

        scope.template = getTemplate(scope.object);
        if (scope.template == null) {
          console.log("No renderer for " + scope.object);
        };
      },
      templateUrl: '/rekall-webconsole/components/runplugin/objectrenderer.html',
    };
  });
})();