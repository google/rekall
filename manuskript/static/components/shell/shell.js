(function() {

  var module = angular.module('manuskript.shell', [
    'manuskript.shell.controller',
    'manuskript.core'
  ]);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('shell', {
      description: 'Shell',
      templateUrl: '/static/components/shell/shell.html',
      hotkey: 's',
      defaultNode: function() {
        return {
          type: 'shell',
          source: "",
          rendered: {
            stderr: "",
            stdout: "",
            result: ""
          }
        };
      }
    });
  });

})();
