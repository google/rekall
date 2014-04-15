(function() {

  var module = angular.module('manuskript.plaintext',
                              ['manuskript.plaintext.controller',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('plaintext', {
      description: 'Plain text',
      defaultNode: function() {
        return {
          type: 'plaintext',
          source: [],
          rendered: []
        };
      }
    });
  });

})();
