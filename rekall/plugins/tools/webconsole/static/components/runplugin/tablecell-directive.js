'use strict';
(function() {

  var module = angular.module('rekall.runplugin.tableCell.directive',
			      ['rekall.runplugin.contextMenu.directive',
			       'rekall.runplugin.objectActions.service']);

  module.directive('rekallTableCell', function(rekallObjectActionsService) {
    return {
      restrict: 'E',
      scope: {
        element: '=',
      },
      require: '^rekallContextMenu',
      link: function(scope, element, attrs, contextMenuCtrl) {
	var data = scope.element.data;
	var renderedData = scope.element.rendered;

      	if (data !== null && data !== undefined && renderedData !== null && renderedData !== undefined) {
	  var newElement;
	  if (rekallObjectActionsService.hasActions(data)) {
	    newElement = angular.element('<span class="interactiveTableCell">' + renderedData + '</span>');
	    newElement.click(function(event) {
	      var actions = rekallObjectActionsService.actionsForObject(data);
	      contextMenuCtrl.showContextMenu(actions, event.pageX, event.pageY);
	      event.stopPropagation();
	    });
	  } else {
	    newElement = angular.element('<span>' + renderedData + '</span>');
	  }

	  element.append(newElement);
	}
      }
    };
  });
})();