(function() {

  var module = angular.module('rekall.runplugin.pluginRegistry.service', []);

  var serviceImplementation = function($http) {
    this.getPlugins = function(successCallback) {
      return $http.get('/rekall/plugins/all', {cache: true}).success(function(response) {
        successCallback(response.data);
      });
    };
  };

  module.service('rekallPluginRegistryService', serviceImplementation);
})();
