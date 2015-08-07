'use strict';
(function() {

  var module = angular.module('rekall.fileupload',
                              ['rekall.fileupload.controller',
                               'angularFileUpload',
                               'manuskript.core']);

  module.run(function(manuskriptCoreNodePluginRegistryService) {
    manuskriptCoreNodePluginRegistryService.registerPlugin('fileupload', {
      description: 'Upload Files',
      templateUrl: '/rekall-webconsole/components/fileupload/fileupload.html',
      hotkey: 'u',
      defaultNode: function() {
        return {
          type: 'fileupload',
          source: {
            size: 0,
            caption: "",
            files: [],
          },
          rendered: {
            caption: "",
          }
        };
      }
    });
  });

})();
