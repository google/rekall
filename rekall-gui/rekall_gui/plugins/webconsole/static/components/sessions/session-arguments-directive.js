'use strict';
(function() {

  var module = angular.module('rekall.sessions.sessionargument.directive',
                              []);

  module.directive('rekallSessionArguments', function($http) {
    return {
      restrict: 'EA',
      templateUrl: '/rekall-webconsole/components/sessions/sessionargument.html',
      scope: {
        session: '=',
      },
    };
  });
})();
