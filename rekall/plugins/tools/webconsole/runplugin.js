(function() {

  var module = angular.module('rekall.runplugin',
                              ['rekall.runplugin.controller',
			       'rekall.runplugin.jsonRenderer.service',
                               'rekall.runplugin.pluginRegistry.service',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('rekallplugin', {
      description: 'Rekall Plugin',
      templateUrl: '/rekall-webconsole/runplugin.html',
      defaultNode: function() {
        return {
          type: 'rekallplugin',
          source: {
            arguments: {}
          },
          rendered: {
            stderr: [],
            stdout: [],
            result: ""
          }
        };
      }
    });
  });

})();
