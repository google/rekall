'use strict';
(function() {

  var module = angular.module('rekall.runplugin.objectActions.init',
			      ['rekall.runplugin.objectActions.service']);

  module.run(function(rekallObjectActionsService) {
    rekallObjectActionsService.registerRunPluginAction(
	'Struct', 'dis',
	function(obj) { return {offset: '0x' + obj['offset'].toString(16)}; },
	'Disassemble', 'Disassemble memory at given offset');
  });

})();