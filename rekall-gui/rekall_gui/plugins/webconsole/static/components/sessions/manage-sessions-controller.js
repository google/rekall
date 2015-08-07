'use strict';
(function() {
  var module = angular.module('rekall.sessions.controller',
                              ['manuskript.core',
                               'manuskript.core.network.service']);

  module.controller('RekallManageSessionController', function(
    $scope, $modalInstance, $http, manuskriptNetworkService, sessions) {

    $scope.data = {
      sessions: sessions,
      state: sessions[0].state
    };

    var updateSessions = function(data) {
      sessions.splice.apply(sessions, [0, sessions.length].concat(data));
    };

    $scope.newSession = function() {
      var new_session = sessions.slice(0);
      new_session.push({});

      $http.post("sessions/update", {
        sessions: new_session,
      }).success(updateSessions);
    };

    $scope.delSession = function(session) {
      var new_session = sessions.slice(0);

      for (var i = 0; i < new_session.length; i++) {
        if (session.session_id == new_session[i].session_id) {
          new_session.splice(i, 1);
          $http.post("sessions/update", {
            sessions: new_session,
          }).success(updateSessions);
          break;
        };
      };
    };

  });
})();
