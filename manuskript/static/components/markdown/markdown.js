(function() {

  var module = angular.module('manuskript.markdown',
                              ['manuskript.markdown.controller',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('markdown', {
      description: 'Markdown',
      defaultNode: function() {
        return {
          type: 'markdown',
          source: [],
          rendered: ""
        };
      }
    });
  });

})();
