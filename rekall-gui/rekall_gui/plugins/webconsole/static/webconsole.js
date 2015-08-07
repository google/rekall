'use strict';
(function() {

  var module = angular.module('rekall.webconsole',
                              ['manuskript.configuration', 'rekall.runplugin',
                              'rekall.fileupload']);
  module.run(function(manuskriptConfiguration) {
    manuskriptConfiguration.pageTitle = 'Rekall Web Console';
    manuskriptConfiguration.nodes = [];
  });

})();
