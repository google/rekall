'use strict';
(function() {

  var module = angular.module('rekall.runplugin.pluginRegistry.service', []);

  var serviceImplementation = function($http) {
    var firstLineOnly = function(str) {
      if (str) {
        return str.split('\n')[0];
      } else {
        return str;
      }
    };

    this.getPlugins = function(successCallback) {
      if (this.plugins != null) {
        successCallback(this.plugins);
        return;
      }

      var self = this;
      return $http.get('/rekall/plugins/all', {cache: true}).success(function(response) {
        for (var key in response) {
          response[key].short_description = firstLineOnly(  // jshint ignore:line
              response[key].description);
        }

        self.plugins = response;

        successCallback(response);
      });
    };
  };

  module.service('rekallPluginRegistryService', serviceImplementation);
})();
