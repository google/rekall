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

        if (addrValue === undefined || addrValue === null) {
          scope.address = '-';
        } else {
          var result = addrValue.toString(16);

          if (result.length < scope.pad) {
            result = new Array(14 - result.length).join('0') + result;
          }
          scope.address = result;
        }
      },
      template: '<samp>0x<span bo-bind="address" /></samp>'
    }
  });

  var templates = {
    'Address': '<addrpad object="object" pad=0 />',
    'Pointer': '<addrpad object="object.target" />',
    'PaddedAddress': '<addrpad object="object.value" pad=14 />',
    'AddressSpace': '{{object.name}}',
    'Enumeration': '<samp class="enum">{{object.enum}} ({{object.value}})</samp>',
    'Literal': '<samp>{{object.value}}</samp>',
    'NativeType': '<samp bo-bind="object.value"></samp>',
    'NoneObject': '<samp tooltip="{{object.reason}}" class="NoneObject">-</samp>',
    'Struct': '<addrpad object="object.offset"/>',
    'UnixTimeStamp': '<samp bo-bind="object.epoch*1000 | date:\'medium\'"</samp>',
    '_EPROCESS': '<samp class="process"><span bo-bind="object.Cybox.Name"/> (<span bo-bind="object.Cybox.PID"/>)</samp>',
    'bool': '<span class="glyphicon" bo-class="{\'glyphicon-ok\': object, \'glyphicon-remove\': !object}"/></span>',
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
        return templates['Address'];

        // Bools are sent as json objects.
      } else if (jQuery.type(item) == 'boolean') {
        return templates['bool'];
      } else {
        return "<samp bo-bind='object'></samp>";
      };
    }

    if (item.mro != null) {
      for (var i = 0; i < item.mro.length; ++i) {
        var template = templates[item.mro[i]];
        if (template !== undefined) {
          return template
        }
      }
    }

    return "<samp bo-bind='object'></samp>";
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

        var template = getTemplate(scope.object);
        if (template) {
          element.html($("<rekall-context-menu object='object' bindonce>").html(template));
          $compile(element.contents())(scope);
        };
      },
    };
  });
})();