'use strict';
(function() {

  var module = angular.module('rekall.runplugin.objectActions.service',
			      ['manuskript.core']);

  var serviceImplementation = function(manuskriptCoreNodePluginRegistryService) {
    var registeredActions = {};

    this.registerAction = function(objType, action, title, description) {
      if (registeredActions[objType] === undefined) {
        registeredActions[objType] = []
      }

      registeredActions[objType].push({
        'action': action,
	'title': title,
	'description': description
      })

    };

    this.registerRunPluginAction = function(objType, pluginName, pluginArgumentsCallback,
					    title, description) {
      this.registerAction(objType, function(obj, scope) {
	var newNode = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin(
          'rekallplugin');
	newNode.source = {
	  'plugin': scope.plugins[pluginName],
	  'arguments': pluginArgumentsCallback(obj),
	};
	newNode.state = 'render';

	var nodesScope = scope;
	while (nodesScope !== undefined &&
               nodesScope.nodes === undefined &&
               nodesScope.addNode === undefined) {
	  nodesScope = nodesScope.$parent;
	}

	if (nodesScope !== undefined) {
	  nodesScope.nodes.push(newNode);
	  nodesScope.selection.node = newNode;
	  nodesScope.selection.nodeIndex = nodesScope.nodes.length - 1;
	} else {
	  throw 'Nodes was not found.';
	}
      }, title, description);
    };


    this.hasActions = function(obj) {
      return this.actionsForObject(obj).length;
    };

    this.actionsForObject = function(obj) {
      var actions = [];
      if (obj.mro) {
	for (var i = 0; i < obj.mro.length; ++i) {
	  var actionsList = registeredActions[obj.mro[i]];
          if (actionsList === undefined) {
            continue
          }

          for (var j = 0; j< actionsList.length; j++) {
	    var wrappedAction = function(action) {
              return {
	        'action': function(scope) {
		  return action.action(obj, scope);
	        }, // jshint ignore:line
	        'title': action.title,
	        'description': action.description
	      };
            }
	    actions.push(wrappedAction(actionsList[j]));
	  }
        }
      }

      return actions;
    };
  };

  module.service('rekallObjectActionsService', serviceImplementation);
})();