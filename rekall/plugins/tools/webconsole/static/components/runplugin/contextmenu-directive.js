'use strict';
(function() {

  var module = angular.module('rekall.runplugin.contextMenu.directive',
                              ['rekall.runplugin.objectActions.service']);

  module.directive('rekallContextMenu', function(rekallObjectActionsService, $timeout) {
    return {
      restrict: 'E',
      scope: {
        object: '=',
      },

      transclude: true,

      controller: function($scope) {
        var menu = $scope.menu = {
          'items': [],
          'visible': false,
          'style': {
            'left': 0,
            'top': 0
          }
        };


        $scope.showContextMenu = this.showContextMenu = function(newMenuItems, x, y) {
          $scope.menu.items = newMenuItems;
          $scope.menu.visible = true;
          $scope.menu.style.left = x;
          $scope.menu.style.top = y;
        }

        this.hideContextMenu = function() {
          menu.visible = false;
        };

        $scope.callItem = function(item, event) {
          item.action($scope);
          event.stopPropagation();
          menu.visible = false;
        };
      },

      link: function(scope , element, attrs) {  // jshint ignore:line
        if (scope.object !== null &&
            rekallObjectActionsService.hasActions(scope.object)) {

          // Add click handlers
          element.click(function(event) {
            var actions = rekallObjectActionsService.actionsForObject(scope.object);

            // Take into account window scrolling.
            $timeout(function () {
              scope.showContextMenu(
                actions, event.pageX, event.pageY - $(window).scrollTop());
            });
          });
        }

        var documentClickHandler = function(event) {  // jshint ignore:line
          if (!scope.menu.visible) {
            return;
          }

          scope.menu.visible = false;
        };

        $(document).bind('click', documentClickHandler);
        scope.$on('$destroy', function() {
          $(document).unbind('click', documentClickHandler);
        });
      },
      templateUrl: '/rekall-webconsole/components/runplugin/contextmenu.html',
    };
  });
})();
