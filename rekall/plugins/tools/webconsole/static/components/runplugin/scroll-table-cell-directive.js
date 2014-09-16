'use strict';
(function() {

  var module = angular.module('rekall.runplugin.tableCell.directive',
                              ['rekall.runplugin.contextMenu.directive',
                               'rekall.runplugin.objectActions.service']);

  module.directive('scrollTableCell', function(rekallObjectActionsService) {
    return {
      restrict: 'E',
      scope: {
        element: '=',
      },
      require: '^rekallContextMenu',
      link: function(scope, element, attrs, contextMenuCtrl) {
        var data = scope.element.data;
        var renderedData = scope.element.rendered;

        if (data !== null && data !== undefined && renderedData !== null &&
            renderedData !== undefined) {
          var newElement;

          if (rekallObjectActionsService.hasActions(data)) {
            newElement = angular.element($('<span class="interactiveTableCell">').html(
              renderedData));

            // Add click handlers for
            newElement.click(function(event) {
              var actions = rekallObjectActionsService.actionsForObject(data);

              // Take into account window scrolling.
              contextMenuCtrl.showContextMenu(
                actions, event.pageX, event.pageY - $(window).scrollTop());
              event.stopPropagation();
            });

          } else {
            newElement = angular.element($('<span>').html(renderedData));
          }

          element.append(newElement);
        }
      }
    };
  });
})();