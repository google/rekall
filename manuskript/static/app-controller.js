/**
 * This should be filled by the code generated on the server.
 * See manuskript/plugin.py for details.
 */
var manuskriptPluginsList = manuskriptPluginsList || [];

(function() {

  var confModule = angular.module('manuskript.configuration', []);
  confModule.value('manuskriptConfiguration', {});

  var module = angular.module('manuskript.app.controller', [
    'manuskript.core',
    'manuskript.load.controller',
    'manuskript.configuration'].concat(manuskriptPluginsList));

  module.controller("ManuskriptAppController", function(
      $scope,
      manuskriptCoreNodePluginRegistryService,
      manuskriptConfiguration) {

    $scope.pageTitle = manuskriptConfiguration.pageTitle || "Manuskript";
    
    /**
     * List of nodes shown to the user.
     */
    $scope.nodes = manuskriptConfiguration.nodes || [];;

    /**
     * Currently edited node, or null if no node is being edited.
     * Only one node can be edited at any given moment.
     */
    $scope.currentlyEditedNode = null;

    /**
     * Adds new node to the list.
     * @param {string} nodeType - Type of node to add.
     */
    $scope.addNode = function(nodeType) {
      var node = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin(
          nodeType);
      $scope.nodes.push(node);
      $scope.editNode(node);
    };

    /**
     * Starts editing of a given node.
     * @param node - Node to edit.
     */
    $scope.editNode = function(node) {
      if ($scope.currentlyEditedNode) {
        $scope.saveNode($scope.currentlyEditedNode);
      }
      node.state = 'edit';
      $scope.currentlyEditedNode = node;
    };

    /**
     * Finishes editing of the node that is currently being edited.
     * @throws {IllegalStateError} If there's no node that's being edited.
     */
    $scope.saveNode = function() {
      if (!$scope.currentlyEditedNode) {
        throw {
          name: 'IllegalStateError',
          message: 'No node is currently being edited'
        };
      }

      $scope.renderNode($scope.currentlyEditedNode);
    };

    /**
     * Renders node.
     * @throws {NotRenderableNodeError} If given node is not renderable.
     */
    $scope.renderNode = function(node) {
      node.state = 'render';
    };

    /**
     * Checks if given node is currently being edited.
     * @returns {boolean} True if node is being edited, false otherwise.
     */
    $scope.isBeingEdited = function(node) {
      return node.state == 'edit';
    };

    /**
     * @returns {string[]} Array of names of available Manuskript plugins.
     */
    $scope.listPlugins = function() {
      return manuskriptCoreNodePluginRegistryService.getAllPlugins();
    };

    /**
     * Returns url of an AngularJS template for the given node. If registered
     * plugin descriptor doesn't have a template url, the url is built based
     * on node type.
     * @param node - Node to get a template for.
     * @returns {string} A url of the AngularJS template for the given node.
     */
    $scope.getIncludedFile = function(node) {
      var pluginDescriptor = manuskriptCoreNodePluginRegistryService.getPlugin(node.type);
      if (pluginDescriptor.templateUrl) {
        return pluginDescriptor.templateUrl;
      } else {
        return "static/components/" + node.type + "/" + node.type + ".html";
      }
    };

    /**
     * Sets state of all the nodes to 'render'.
     */
    $scope.renderAll = function() {
      for (var i = 0; i < $scope.nodes.length; ++i) {
        var node = $scope.nodes[i];
	node.state = "render";
      }
    };

    /**
     * Loads list of nodes from the local JSON file. File object is expeted
     * to be in the current scope ($scope.fileToLoad).
     */
    $scope.loadFile = function() {
      var reader = new FileReader();
      reader.onload = function(e) {
        $scope.nodes = angular.fromJson(reader.result);
        $scope.$apply();
      };
      reader.readAsText($scope.fileToLoad);
    };

    /**
     * Saves list of nodes to the local JSON file. File name is expected to
     * be in the current scope ($scope.fileToSave).
     */
    $scope.saveFile = function() {
      var blob = new Blob([angular.toJson($scope.nodes)], {type: "text/json;charset=utf-8"});
      saveAs(blob, $scope.fileToSave);
    };
  });

})();
