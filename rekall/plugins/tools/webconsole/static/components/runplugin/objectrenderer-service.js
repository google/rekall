'use strict';
(function() {

  var module = angular.module('rekall.runplugin.objectRenderer.service', []);

  var serviceImplementation = function($filter) {
    var addrpad = function(addrValue) {
      if (addrValue === undefined || addrValue === null) {
	return '-';
      }

      var result = addrValue.toString(16);
      if (result.length < 14) {
	result = new Array(14 - result.length).join('0') + result;
      }
      result = '0x' + result;
      return result;
    };

    var renderers = {
      'Literal': function(item) { return item.value; },
      'Struct': function(item) {
	if (item.value !== undefined) {
          return item.value.toString();
	} else {
	  return addrpad(item.offset);
	}
      },
      'NativeType': function(item) { return item.value; },
      'Pointer': function(item) { return item.value; },
      'AddressSpace': function(item) { return item.name; },
      'NoneObject': function(item) { return '-'; }, // jshint ignore:line
      'UnixTimeStamp': function(item) {
	if (!item.epoch) {
          return '-';
	} else {
          return $filter('date')(item.epoch * 1000, 'medium');
	}
      },
      'Enumeration': function(item) {
        return item.enum + ' (' + item.value + ')';
      },
      '_EPROCESS': function(item) {
        return item.Cybox.Name + ' (' + item.Cybox.PID + ')';
      },
      'TreeNode': function(item) {
	var result = '';
	for (var i = 0; i < item.depth; ++i) {
	  result += '* ';
	}
	result += this.render(item.child);
	return result;
      },

      'Address': function(item) {
	if (item.value === undefined || item.value === null) {
	  return '-';
	}

	return '0x' + item.value.toString(16);
      },

      'PaddedAddress': function(item) {
	return addrpad(item.value);
      },

      'object': function() {
	return '';
      }
    };

    this.render = function(item) {
      var renderer;

      if (!(item instanceof Object)) {
	if (item === null || item === undefined) {
	  return '-';
	} else {
	  return item.toString();
	}
      }

      // Check the item's mro for specialized renderers.
      if (item.mro) {
        for (var i = 0; i < item.mro.length; ++i) {
          renderer = renderers[item.mro[i]];
          if (renderer !== undefined) {
	    break;
          }
         }
       }

      if (renderer !== undefined) {
	return renderer(item);
      } else {
	return item;
      }
    };
  };

  module.service('rekallObjectRendererService', serviceImplementation);
})();