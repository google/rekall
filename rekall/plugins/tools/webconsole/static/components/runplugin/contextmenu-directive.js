'use strict';
(function() {

  var module = angular.module('rekall.runplugin.contextMenu.directive',
                              ['rekall.runplugin.objectActions.service',
                               'ui.bootstrap']);

  // This directive creates a context menu around a Rekall object.
  module.directive('rekallContextMenu', function(
    rekallObjectActionsService, $modal, $timeout) {
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
      },

      link: function(scope , element, attrs) {  // jshint ignore:line
        scope.showContextMenu = function(newMenuItems, x, y) {
          scope.menu.items = newMenuItems;
          scope.menu.visible = true;
          scope.menu.style.left = x;
          scope.menu.style.top = y;
        }

        scope.callItem = function(item, event) {
          event.stopPropagation();

          item.action(scope);
          scope.menu.visible = false;

          return false;
        };

        if (scope.object !== null &&
            rekallObjectActionsService.hasMenuItems(scope.object)) {

          // This object has actions.
          scope.actionable = true;

          // Add click handlers
          element.click(function(event) {
            var items = rekallObjectActionsService.menuItemsForObject(scope.object);

            // Take into account window scrolling.
            $timeout(function () {
              scope.showContextMenu(
                items, event.pageX, event.pageY - $(window).scrollTop());


              var documentClickHandler = function(event) {
                scope.menu.visible = false;
                $(document).unbind('click', documentClickHandler);
                scope.$apply();

                event.stopPropagation();
              };

              $(document).bind('click', documentClickHandler);
            });

            event.stopPropagation();
          });
        }
      },
      templateUrl: '/rekall-webconsole/components/runplugin/contextmenu.html',
    };
  });
})();
