'use strict';
(function() {

  var module = angular.module('rekall.runplugin.pluginRegistry.service', [
    'manuskript.configuration',
  ]);

  var serviceImplementation = function($http, manuskriptConfiguration) {
    var firstLineOnly = function(str) {
      if (str) {
        return str.split('\n')[0];
      } else {
        return str;
      }
    };

    this.getPlugins = function(successCallback, session_id) {
      var self = this;
      if (angular.isUndefined(session_id)) {
        session_id = manuskriptConfiguration.default_session.session_id;
      };

      return $http.get('/rekall/plugins/all/' + session_id).success(
          function(response) {
            for (var key in response) {
              response[key].short_description = firstLineOnly(  // jshint ignore:line
                response[key].description);
            }

            successCallback(response);
          });
    };
  };

  module.service('rekallPluginRegistryService', serviceImplementation);
})();
