'use strict';
(function() {

  var module = angular.module('rekall.runplugin.contextMenu.directive',
                              ['rekall.runplugin.objectActions.service',
                               'ui.bootstrap']);

  // This directive creates a context menu around a Rekall object.
  module.directive('rekallContextMenu', function(
    rekallObjectActionsService, $timeout) {
    return {
      restrict: 'E',
      scope: {
        object: '=',
      },
      transclude: true,

      link: function(scope , element, attrs) {  // jshint ignore:line
        // Find a scope in the parent scope chain where there's a
        // RekallRunPluginController.
        var currentScope = scope;
        while (currentScope) {
          if (angular.isDefined(currentScope.node) &&
              angular.isDefined(currentScope.pushSources)) {
            scope.sessionId = currentScope.node.source.session_id;
            break;
          } else {
            currentScope = currentScope.$parent;
          }
        }
        
        // Fill items list.
        scope.items = rekallObjectActionsService.menuItemsForObject(
          scope.object);
        scope.actionable = false;
        
        angular.forEach(scope.items, function(item) {
          if (!item.description) {
            item.description = '';
          }
        });
        
        scope.showContextMenu = function(x, y) {
          var menu = $(element).find('ul');
          menu.show();
          menu.offset({top: y, left: x});
        };

        scope.hideContextMenu = function() {
          $(element).find('ul').hide();
        };
        // Hide the menu by default.
        scope.hideContextMenu();

        scope.callItem = function(item, event) {
          event.stopPropagation();

          item.action(scope);

          // Hide menu when any item is clicked.
          scope.hideContextMenu();
          return false;
        };

        if (scope.object != null &&
            rekallObjectActionsService.hasMenuItems(scope.object)) {

          // This object has actions.
          scope.actionable = true;

          // Add click handlers
          element.click(function(event) {
            // Take into account window scrolling.
            $timeout(function () {
              scope.showContextMenu(
                event.pageX, event.pageY);

              var documentClickHandler = function(event) {
                scope.hideContextMenu();
                $(document).unbind('click', documentClickHandler);

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
