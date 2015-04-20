(function() {

  var module = angular.module('manuskript.pythoncall',
                              ['manuskript.pythoncall.controller',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('pythoncall', {
      description: 'Python',
      templateUrl: '/static/components/pythoncall/pythoncall.html',
      defaultNode: function() {
        return {
          type: 'pythoncall',
          source: [],
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
