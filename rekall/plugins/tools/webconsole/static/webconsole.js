'use strict';
(function() {

  var module = angular.module('rekall.webconsole',
                              ['manuskript.configuration', 'rekall.runplugin']);
  module.run(function(manuskriptConfiguration) {
    manuskriptConfiguration.pageTitle = 'Rekall Web Console';
    manuskriptConfiguration.nodes = [];
  });

})();
