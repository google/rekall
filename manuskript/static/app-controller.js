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
    'pasvaz.bindonce',
    'manuskript.configuration'].concat(manuskriptPluginsList));

  module.controller("ManuskriptAppController", function(
      $scope, $modal, $timeout, $sce,
      manuskriptCoreNodePluginRegistryService,
      manuskriptConfiguration) {

    $scope.pageTitle = manuskriptConfiguration.pageTitle || "Manuskript";

    /**
     * List of nodes shown to the user.
     */
    $scope.nodes = manuskriptConfiguration.nodes || [];;

    $scope.selection = {
      node: null,
      nodeIndex: -1
    };

    /**
     * Returns CSS class of a cell corresponding to the given node.
     * @param node - New node will be added before this node..
     * @returns {string} CSS class name.
     */
    $scope.cellClass = function(node) {
      if ($scope.selection.node === node) {
	return ["cell", "selected"];
      } else {
	return ["cell"];
      }
    }

    /**
     * When selected node or index of the selected node changes (index changes
     * when node is moved), scroll the screen to show the node, unless it's
     * already visible.
     */
    var selectionChangeHandler = function(newValue, oldValue) {
      if (newValue != null && newValue !== oldValue) {
	var scrollIntoCell = function() {
	  var selectedCell = angular.element("#cells .cell.selected");
	  if (selectedCell.length > 0) {
	    var cellTop = selectedCell.offset().top;
	    var cellHeight = selectedCell.height();
	    var windowScrollTop = angular.element(window).scrollTop();
	    var windowHeight = window.innerHeight;

	    var elementVisible = (cellTop > windowScrollTop &&
		cellTop < (windowScrollTop + windowHeight) ||
		(cellTop + cellHeight) > windowScrollTop &&
		(cellTop + cellHeight) < (windowScrollTop + windowHeight));

	    if (!elementVisible) {
	      angular.element(window).scrollTop(Math.max(0, cellTop - 40));
	    }
	  } else {
	    $timeout(scrollIntoCell);
	  }
	}
	$timeout(scrollIntoCell);
      }
    };
    $scope.$watch('selection.node', selectionChangeHandler);
    $scope.$watch('selection.nodeIndex', selectionChangeHandler);

    /**
     * If selection changes, forced saving of the previous node.
     */
    $scope.$watch('selection.node', function(newValue, oldValue) {
      $scope.saveNode(oldValue);
    });

    /**
     * When selected node changes, update selected node index.
     */
    $scope.$watchCollection('nodes', function() {
      $scope.selection.nodeIndex = $scope.nodes.indexOf($scope.selection.node);
    });

    /**
     * Adds new node to the list.
     * @param {string} nodeType - Type of node to add.
     * @param {int=} beforeNodeIndex - Optional, if defined, the node will be
     *                                 inserted into the list of nodes before
     *                                 the element with this index.
     */
    $scope.addNode = function(nodeType, beforeNodeIndex) {
      if (beforeNodeIndex === undefined) {
	beforeNodeIndex = $scope.nodes.length;
      }

      var modalInstance = $modal.open({
	templateUrl: 'static/components/core/addnode-dialog.html',
	controller: 'AddNodeDialogController',
	resolve: {
	  items: function() {
	    return $scope.listPlugins();
	  }
	}
      });

      modalInstance.result.then(function(typeKey) {
	var node = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin(
            typeKey);

	$scope.nodes.splice(beforeNodeIndex, 0, node);
	$scope.editNode(node);
      });
    };

    /**
     * Add new node before given node.
     * @param node - New node will be added before this node..
     */
    $scope.addNodeBefore = function(node) {
      $scope.addNode(node.type, $scope.nodes.indexOf(node));
    };

    /**
     * Add new node after given node.
     * @param node - New node will be added after this node..
     */
    $scope.addNodeAfter = function(node) {
      $scope.addNode(node.type, $scope.nodes.indexOf(node) + 1);
    };

    /**
     * Duplicate given node in a list.
     * @param node - Node to be duplicated. Duplicate will be inserted right
     *               after this node.
     */
    $scope.duplicateNode = function(node) {
      var newNode = angular.copy(node);
      var nodeIndex = $scope.nodes.indexOf(node);
      $scope.nodes.splice(nodeIndex + 1, 0, newNode);
    };

    /**
     * Starts editing of a given node.
     * @param node - Node to edit.
     */
    $scope.editNode = function(node) {
      $scope.selection.node = node;
      node.state = 'edit';
    };

    /**
     * Finishes editing of the node that is currently being edited.
     * @param node - Node to be saved. If not specified, currently selected
     *               node will be used.
     */
    $scope.saveNode = function(node) {
      if (node === undefined) {
	node = $scope.selection.node;
      }

      if (node != null && node.state == 'edit') {
	$scope.renderNode(node);
      }
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
     * Checks if given node can be moved up in the list.
     * @returns {boolean} True if node can be moved.
     */
    $scope.canMoveNodeUp = function(node) {
      return $scope.nodes.indexOf(node) > 0;
    }

    /**
     * Checks if given node can be moved down in the list.
     * @returns {boolean} True if node can be moved.
     */
    $scope.canMoveNodeDown = function(node) {
      return $scope.nodes.indexOf(node) < $scope.nodes.length - 1;
    }

    /**
     * Moves node up in the list.
     */
    $scope.moveNodeUp = function(node) {
      var nodeIndex = $scope.nodes.indexOf(node);
      $scope.nodes.splice(nodeIndex, 1);
      $scope.nodes.splice(nodeIndex - 1, 0, node);
    }

    /**
     * Moves node down in the list.
     */
    $scope.moveNodeDown = function(node) {
      var nodeIndex = $scope.nodes.indexOf(node);
      $scope.nodes.splice(nodeIndex, 1);
      $scope.nodes.splice(nodeIndex + 1, 0, node);
    }

    /**
     * Removes node from the list.
     */
    $scope.removeNode = function(node) {
      var nodeIndex = $scope.nodes.indexOf(node);
      $scope.nodes.splice(nodeIndex, 1);

      if ($scope.selection.node === node) {
	$scope.selection.node = null;
      }
    }

    /**
     * Clears the list of nodes.
     */
    $scope.removeAllNodes = function() {
      // It's better to modify the nodes array than to assign new array to the
      // scope variable. Some details:
      // https://github.com/angular/angular.js/wiki/Understanding-Scopes#ngRepeat:
      $scope.nodes.splice(0, $scope.nodes.length);
    }

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
        return $sce.trustAsResourceUrl(pluginDescriptor.templateUrl);
      } else {
        return $sce.trustAsResourceUrl("static/components/" + node.type + "/" + node.type + ".html");
      }
    };

    /**
     * Sets state of all the nodes to 'render'.
     */
    $scope.renderAllNodes = function() {
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
