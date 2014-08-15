'use strict';
(function() {

  var module = angular.module('rekall.runplugin.freeFormat.directive',
			      ['rekall.runplugin.contextMenu.directive',
			       'rekall.runplugin.objectActions.service']);

  module.directive('rekallFreeFormat', function(rekallObjectActionsService) {
    return {
      restrict: 'E',
      scope: {
        element: '=',
      },
      require: '^rekallContextMenu',
      link: function(scope, element, attrs, contextMenuCtrl) {
	var format = scope.element.renderedData[0];
	var components = [];
	var prevPos = 0;
	format.replace(/\{(\d+)(?:\:.+?\}|\})/g, function(match, argPos, offset) {
	  argPos = parseInt(argPos) + 1;
	  components.push({type: 'literal',
			   value: format.substring(prevPos, offset)});
	  components.push({type: 'argument',
			   rendered: scope.element.renderedData[argPos],
			   value: scope.element.data[argPos]});

	  prevPos = offset + match.length;
	});
	if (prevPos < format.length) {
	  components.push({type: 'literal',
			   value: format.substring(prevPos, format.length)});
	}

	for (var i = 0; i < components.length; ++i) {
	  var component = components[i];
	  if (component.type === 'literal') {
	    element.append(component.value);
	  } else if (component.type === 'argument') {
	    var value = component.value;

	    var newElement;
	    if (value !== null && value !== undefined && rekallObjectActionsService.hasActions(value)) {
	      newElement = angular.element('<span class="freeFormatArgument">' + component.rendered + '</span>');

	      newElement.click(function(event) {
		var actions = rekallObjectActionsService.actionsForObject(value);
		contextMenuCtrl.showContextMenu(actions, event.pageX, event.pageY);
		event.stopPropagation();
	      }); // jshint ignore:line
	    } else {
	      newElement = angular.element('<span>' + component.rendered + '</span>');
	    }

	    element.append(newElement);
	  } else {
	    throw 'Invalid component type: ' + component.type;
	  }
	}
      }
    };
  });
})();