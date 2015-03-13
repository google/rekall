(function() {

  var module = angular.module('manuskript.core.network.service', [
    'manuskript.core']);

  var serviceImplementation = function($http) {

    this.callServer = function(endpoint, kwargs) {
      var socket = new WebSocket('ws://' + location.host + "/" + endpoint);

      socket.onopen = function(msg) {  // jshint ignore:line
	socket.send(angular.toJson(kwargs.params || {}));
      };

      socket.onerror = function(error) {  // jshint ignore:line
	// TDO(mbushkov): implement proper error handling
      };

      if (kwargs.onclose) {
	socket.onclose = kwargs.onclose;
      };

      if (kwargs.onmessage) {
        socket.onmessage = function(event) {
	  var jsonOutput = JSON.parse(event.data);
          kwargs.onmessage(jsonOutput);
        };
      };
    };

  };

  module.service('manuskriptNetworkService', serviceImplementation);
})();
