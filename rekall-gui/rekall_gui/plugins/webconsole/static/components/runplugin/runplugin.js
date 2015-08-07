'use strict';
(function() {

  var module = angular.module('rekall.runplugin', [
    'rekall.runplugin.controller',
    'manuskript.core',
    'manuskript.configuration',
  ]);

  module.run(function(manuskriptCoreNodePluginRegistryService,
                      manuskriptConfiguration) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('rekallplugin', {
      description: 'Rekall Plugin',
      templateUrl: '/rekall-webconsole/components/runplugin/runplugin.html',
      hotkey: 'r',
      defaultNode: function() {
        return {
          type: 'rekallplugin',
          source: {
            arguments: {},
            session_id: manuskriptConfiguration.default_session.session_id,
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
