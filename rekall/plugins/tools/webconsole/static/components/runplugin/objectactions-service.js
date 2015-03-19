'use strict';
(function() {

  var module = angular.module('rekall.runplugin.objectActions.service',
                              ['manuskript.core',
                               'rekall.runplugin.pluginRegistry.service']);

  var serviceImplementation = function(
    manuskriptCoreNodePluginRegistryService, rekallPluginRegistryService, $modal) {

    // These handlers are registered for each object type. When we render the
    // object, we decide based on its MRO which handler should be responsible
    // for its context menu.

    // function handler(obj):

    // A handler must return an array of objects describing each context menu
    // entry. Each object should have the following parameters:

    // title: The name of the menu entry.
    // description: The tooltip of the menu entry.
    // action: A callable which will run when the menu entry is selected.
    var registeredHandlers = {};

    // Register a new object type handler.
    this.registerHandler = function(objType, handler) {
      registeredHandlers[objType] = handler;
    };

    this.menuItemsForObjectWithType = function(obj, objType) {
      return registeredHandlers[objType](obj) || [];
    };


    // Returns a list of context menu entries for this object.
    this.menuItemsForObject = function(obj) {
      if (obj.mro) {
        var mro = obj.mro.split(":");

        for (var i = 0; i < mro.length; ++i) {
          if (registeredHandlers[mro[i]]) {
            return registeredHandlers[mro[i]](obj);
          }
        };
      }

      return [];
    };


    this.createNewRekallModal = function($scope, pluginName, pluginArgs, sessionId) {
      var newNodeModel = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin('rekallplugin');

      rekallPluginRegistryService.getPlugins(function(plugins) {
        var newNode = angular.copy(newNodeModel);
        newNode.source = {
          plugin: plugins[pluginName],
          arguments: pluginArgs,
          session_id: $scope.object.session_id,
        };

        $scope.node = newNode;
        $scope.node.state = "render";

        // Open a model with the correct template.
        $modal.open({
          templateUrl: '/rekall-webconsole/components/runplugin/runplugin.html',
          scope: $scope,
          size: 'lg',
          windowClass: "wide-modal"
        });

      });
    };

    this.createNewRekallCell = function($scope, pluginName, pluginArgs) {
        var newNode = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin(
          'rekallplugin');

        rekallPluginRegistryService.getPlugins(function(plugins) {
          newNode.source = {
            'plugin': plugins[pluginName],
            'arguments': pluginArgs,
            'session_id': $scope.sessionId
          };

          var nodesScope = $scope;

          while (nodesScope !== undefined &&
                 nodesScope.nodes === undefined &&
                 nodesScope.addNode === undefined) {
            nodesScope = nodesScope.$parent;
          }

          if (nodesScope !== undefined) {
            nodesScope.nodes.push(newNode);
            nodesScope.selection.node = newNode;
          } else {
            throw 'Nodes was not found.';
          }

          nodesScope.renderNode(newNode);
        });
    };


    this.hasMenuItems = function(obj) {
      return this.menuItemsForObject(obj).length;
    };
  };

  module.service('rekallObjectActionsService', serviceImplementation);
})();
