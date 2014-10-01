'use strict';
(function() {

  var module = angular.module('rekall.runplugin',
                              ['rekall.runplugin.controller',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('rekallplugin', {
      description: 'Rekall Plugin',
      templateUrl: '/rekall-webconsole/components/runplugin/runplugin.html',
      hotkey: 'r',
      defaultNode: function() {
        return {
          type: 'rekallplugin',
          source: {
            arguments: {}
          },
          rendered: {
            stderr: [],
            stdout: [],
            result: ''
          }
        };
      }
    });
  });

})();
