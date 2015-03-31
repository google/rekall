(function() {

  var module = angular.module('manuskript.pythoncall.renderer.service', []);

  /**
   * 'manuskriptPythonCallRendererService' service sends requests to the server
   * and executes success/failure callbacks asyncrhonously. It guarantess that
   * requests will be sent in the same order as
   * manuskriptPythonCallRendererService.Render() calls and that each request
   * will only be sent when the previous one is complete.
   */
  var serviceImplementation = function($http, $interval) {
    this.renderingQueue = [];
    this.inProgress = null;

    /**
     * Send the request to the server.
     * @param {object} param - Arbitrary json-serializable object that will be
                                sent to the server as request's body.
     * @param {string} url - Which server URL to use.
     * @param {function} successCallback - Callback function to be called on
     *                                     success.
     * @param {function} failureCallback - Callback function to be called on
     *                                     failure.
     */
    this.Render = function(param, url, successCallback, failureCallback) {
      this.renderingQueue.push([param, url, successCallback, failureCallback]);
    };


    var self = this;
    this.RenderPoll = function() {
      if (self.renderingQueue.length > 0 && !self.inProgress) {
        self.inProgress = self.renderingQueue.shift();
        var param = self.inProgress[0];
        var url = self.inProgress[1];
        var successCallback = self.inProgress[2];
        var failureCallback = self.inProgress[3];
        $http.post(url, param).success(
	  function(data, status, headers, config) {
	    self.inProgress = null;
	    successCallback(data);
	  }).error(function(data) {
            self.inProgress = null;
            failureCallback(data);
          });
      }
    };

    $interval(this.RenderPoll, 50);
  };

  module.service('manuskriptPythonCallRendererService', serviceImplementation);
})();
