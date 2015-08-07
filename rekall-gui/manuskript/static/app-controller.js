/**
 * This should be filled by the code generated on the server.
 * See manuskript/plugin.py for details.
 */
var manuskriptPluginsList = manuskriptPluginsList || [];

(function() {

  var confModule = angular.module('manuskript.configuration', []);

  // Incorporate configuration from the HTML generator into the global app
  // configuration. This will be available everywhere as scope.app-config .
  confModule.value('manuskriptConfiguration', $('html').data());

  var module = angular.module('manuskript.app.controller', [
    'manuskript.core',
    'manuskript.core.network.service',
    'manuskript.load.controller',
    'rekall.sessions.sessionargument.directive',
    'rekall.sessions.controller',
    'cfp.hotkeys',
    'manuskript.configuration',
  ].concat(manuskriptPluginsList));

  module.controller("ManuskriptAppController", function(
    $scope, $modal, $timeout, $sce, $upload, $http, hotkeys,
    manuskriptCoreNodePluginRegistryService, manuskriptNetworkService,
    manuskriptConfiguration) {

    $scope.app_config = manuskriptConfiguration;

    $scope.margin_width = 2;
    $scope.main_width = 8;

    $scope.pageTitle = manuskriptConfiguration.pageTitle || "Manuskript";

    $scope.toggleMainWidth = function() {
      if ($scope.margin_width == 2) {
        $scope.margin_width = 0;
        $scope.main_width = 12;
      } else {
        $scope.margin_width = 2;
        $scope.main_width = 8;
      };
    };


    /**
     * A node represents the state of the cell. A node has the following fields:
     * - id: This is a unique number representing a unique configuration of the
     *   cell. Note that it can be used to cache cell data - id will change
     *   whenever the cell's content changes.
     *
     * - source: This is an object describing the source parameters for the
     *   cell. Cells are assumed to be stable relative to the source object -
     *   i.e. if the source has not changed, the cell is not changed.
     *
     * - type: This is the type of plugin handling the cell.
     *
     * Node state life cycle:
     *
     * 1) Nodes get created into the 'edit' state. Templates can detect the edit
     * state by testing node.state == 'edit'. Existing nodes can switch to the
     * edit state by calling $scope.editNode(node).
     *
     * 2) When the user click on the button, they are moved into the 'render'
     * state (by calling the $scope.renderNode(node) function. If the
     * node.source has not changed, the node switches to the show state
     * immediately, otherwise it switches to the 'render' state.
     *
     * 3) Plugins should watch for the node's state to enter the render
     * state. At this point the node.source object should be stable and can be
     * processed. When the plugin finished processing it should call
     * $scope.showNode(node) to move to the 'show' state.
     *
     * 4) Plugins should render the final view of the cell in the 'show' state,
     * perhaps using intermediate data created during the 'render' state.
     *
     * Note - do not manipulate the state directly - only use the below
     * functions. Plugins are probably only interested in watching for the
     * 'render' state.
     */
    /**
     * Starts editing of a given node.
     * @param node - Node to edit.
     */
    $scope.editNode = function(node) {
      if ($scope.app_config.mode == "static")
        return;

      $scope.selection.node = node;

      // Maintain a copy of the old state so we can check for changes.
      node.old_source = angular.copy(node.source);
      node.state = 'edit';
    };

    /**
     * Moves the node into the rendered state. If the node's source has not
     * changed we can skip the render state and move right into the show state.
     *
     * @throws {NotRenderableNodeError} If given node is not renderable.
     */
    $scope.renderNode = function(node) {
      if (angular.isUndefined(node)) {
        node = $scope.selection.node;
      }

      if (node != null) {
        if (angular.equals(node.old_source, node.source)) {
          node.state = 'show';
        } else {
          node.state = 'render';
          $scope.uploadDocument();
        }
      }
    };

    /**
     * Move the node from the rendered state to the 'show' state.
     *
     */
    $scope.showNode = function(node) {
      node.state = 'show';
    };

    /**
     * List of nodes shown to the user.
     */
    $scope.nodes = manuskriptConfiguration.nodes || [];;

    $scope.selection = {
      node: null,
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
    $scope.$watchCollection('nodes', selectionChangeHandler);

    /**
     * If selection changes during an edit, move the previous node into the
     * render state (Same as submitting it). Do nothing at other times.
     *
     */
    $scope.$watch('selection.node', function(newValue, oldValue) {
      if (oldValue && oldValue.state == 'edit') {
        $scope.renderNode(oldValue);
      };
    });

    /**
     * Adds new node to the list.
     * @param {int=} beforeNodeIndex - Optional, if defined, the node will be
     *                                 inserted into the list of nodes before
     *                                 the element with this index.
     */
    $scope.addNode = function(nodeIndex, nodeType) {
      // If the node is not specified we add it after the current selection.
      if (nodeIndex == null) {
        nodeIndex = $scope.nodes.indexOf($scope.selection.node);
      };

      if (nodeIndex === -1) {
        nodeIndex = $scope.nodes.length;
      };

      var addNodeType = function(typeKey) {
        var node = manuskriptCoreNodePluginRegistryService.createDefaultNodeForPlugin(
            typeKey);

        $scope.nodes.splice(nodeIndex + 1, 0, node);
        $scope.editNode(node);
      }

      if (nodeType == null) {
        var modalInstance = $modal.open({
          templateUrl: '/static/components/core/addnode-dialog.html',
          controller: 'AddNodeDialogController',
          resolve: {
            items: function() {
              return $scope.listPlugins();
            }
          }
        }).result.then(addNodeType);
      } else {
        addNodeType(nodeType);
      };
    };

    $scope.getSessionByID = function(session_id) {
      for(var i=0; i < manuskriptConfiguration.sessions.length; i++) {
        if(session_id == manuskriptConfiguration.sessions[i]) {
          return manuskriptConfiguration.sessions[i];
        };
      };
    };

    $scope.manageSession = function() {
      var newScope = $scope.$new();
      newScope.data = {
        sessions: manuskriptConfiguration.sessions,
        state: manuskriptConfiguration.sessions[0].state,
      };

      $scope.$on('$destroy', function() {
        newScope.$destroy();
      });

      /* Update the sessions on the server. */
      var updateServerSessions = function () {
        // Send the nodes to the server for storage.
        $http.post("sessions/update", {
          sessions: manuskriptConfiguration.sessions,
        }).success(function(data) {
          manuskriptConfiguration.sessions = data;
        });
      };

      var modalInstance = $modal.open({
        templateUrl: '/rekall-webconsole/components/sessions/manage-sessions.html',
        controller: "RekallManageSessionController",
        scope: $scope,
        resolve: {
          sessions: function() {
            return manuskriptConfiguration.sessions;
            }
        },
        windowClass: "wide-modal",
      }).result.then(updateServerSessions, updateServerSessions);
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

      if (nodeIndex > 0) {
        $scope.nodes.splice(nodeIndex, 1);
        $scope.nodes.splice(nodeIndex - 1, 0, node);
      };
    }

    /**
     * Moves node down in the list.
     */
    $scope.moveNodeDown = function(node) {
      var nodeIndex = $scope.nodes.indexOf(node);

      if (nodeIndex < $scope.nodes.length - 1) {
        $scope.nodes.splice(nodeIndex, 1);
        $scope.nodes.splice(nodeIndex + 1, 0, node);
      };
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
     *
     * This is the core of the plugin registry system - by emitting a different
     * template here for each node, a different controller can be used for each
     * node. The controller then sets up watchers on the node itself. The choice
     * of node template occurs based on the node.type element.
     *
     * @param node - Node to get a template for.
     * @returns {string} A url of the AngularJS template for the given node.
     */
    $scope.getIncludedFile = function(node) {
      if (node ==null) return;

      var pluginDescriptor = manuskriptCoreNodePluginRegistryService.getPlugin(node.type);
      if (pluginDescriptor.templateUrl) {
        return $sce.trustAsResourceUrl(pluginDescriptor.templateUrl);
      } else {
        return $sce.trustAsResourceUrl(
          "/static/components/" + node.type + "/" + node.type + ".html");
      }
    };

    /**
     * Sets state of all the nodes to 'render'.
     */
    $scope.renderAllNodes = function() {
      for (var i = 0; i < $scope.nodes.length; ++i) {
        var node = $scope.nodes[i];
        $scope.renderNode(node);
      }
    };

    $scope.loadSessionsFromServer = function() {
      $http.get('worksheet/load_nodes').success(function(result) {
        manuskriptConfiguration.sessions = result.sessions;
        manuskriptConfiguration.sessionsById = {}
        for(var i=0; i < result.sessions.length; i++) {
          var session_id = result.sessions[i].session_id;
          manuskriptConfiguration.sessionsById[session_id] = result.sessions[i];
          manuskriptConfiguration.sessionsById["" + session_id] =
            result.sessions[i];
        };

        if(angular.isUndefined(manuskriptConfiguration.default_session)) {
          manuskriptConfiguration.default_session = result.sessions[0];
        };
      });
    };

    $scope.loadNodesFromServer = function() {
      $scope.removeAllNodes();

      $http.get('worksheet/load_nodes').success(function(result) {
        if (result.filename) {
          var components = result.filename.split("/");
          $scope.worksheet_filename = components[components.length-1];
        }
        $scope.nodes = result.cells;
        manuskriptConfiguration.sessions = result.sessions;
        manuskriptConfiguration.sessionsById = {}
        for(var i=0; i < result.sessions.length; i++) {
          var session_id = result.sessions[i].session_id;
          manuskriptConfiguration.sessionsById[session_id] = result.sessions[i];
          manuskriptConfiguration.sessionsById["" + session_id] =
            result.sessions[i];
        };

        if(angular.isUndefined(manuskriptConfiguration.default_session)) {
          manuskriptConfiguration.default_session = result.sessions[0];
        };

        $scope.renderAllNodes();
      });
    };

    $scope.uploadDocument = function() {
      var cells = [];

      for (var i = 0; i < $scope.nodes.length; i++) {
        var node = $scope.nodes[i];

        // Only copy the minimum set of attributes from the node for storage.
        cells.push({
          // Need to use angular.copy to have angular remove its own pollution
          // from this object (i.e. various watchers and scope things).
          source: angular.copy(node.source), // Private plugin specific data for this node.
          type: node.type,                   // The type of this cell (used to
                                             // invoke the right plugin).
          id: node.id,                       // Retain the node id.
        });
      };

      // Send the nodes to the server for storage.
      if ($scope.app_config.mode != "static") {
        manuskriptNetworkService.callServer("rekall/document/upload", {
          params: cells
        });
      };
    };

    // If node order changes we refresh the server document.
    $scope.$watchCollection("nodes", $scope.uploadDocument);

    // If sessions changes we refresh the server document.
    $scope.$watchCollection(
      "manuskriptConfiguration.sessions", $scope.uploadDocument);

    $scope.uploadWorksheet = function($files) {
      var file = $files[0];

      $scope.upload = $upload.upload({
        url: '/uploads/worksheet',
        data: {
          type: file.type
        },
        file: file,
      }).success(function(data, status, headers, config) {
        // When successfully uploaded we just refresh the entire page to start
        // with a new state.
        location.reload();
      });
    };

    // Save the current worksheet on the server in the worksheet directory.
    $scope.saveWorksheet = function() {
      var newScope = $scope.$new(true);

      $modal.open({
        templateUrl: '/static/components/core/file-selector-new.html',
        controller: 'FileSelectorController',
        scope: newScope,
      });
    };

    $scope.openWorksheet = function() {
      var newScope = $scope.$new(true);

      $modal.open({
        templateUrl: '/static/components/core/file-selector.html',
        controller: 'FileSelectorController',
        scope: newScope,
      });
    };


    hotkeys.bindTo($scope)
      .add({
        combo: 'ctrl+a',
        description: 'Add new cell after selection.',
        callback: function(event) {
          event.preventDefault();
          $scope.addNode();

          return false;
        }
      })

      .add({
        combo: 'ctrl+o',
        description: 'Open worksheet.',
        callback: function(event, hotkey) {
          // Stop the browser's ctrl-o shortcut.
          event.preventDefault();
          $scope.openWorksheet();

          return false;
        }
      })

      .add({
        combo: 'ctrl+up',
        description: 'Move cell up.',
        callback: function () {
          $scope.moveNodeUp($scope.selection.node);
        },
      })

      .add({
        combo: 'ctrl+down',
        description: 'Move cell down.',
        callback: function () {
          $scope.moveNodeDown($scope.selection.node);
        },
      })

      .add({
        combo: 'shift+up',
        description: 'Move cell selection up.',
        callback: function () {
          if ($scope.selection.node == null) {
            $scope.selection.node = $scope.nodes[0];
            return;
          };

          var nodeIndex = $scope.nodes.indexOf($scope.selection.node);
          if (nodeIndex > 0) {
            $scope.selection.node = $scope.nodes[nodeIndex - 1];
          }
        },
      })

      .add({
        combo: 'shift+down',
        description: 'Move cell selection down.',
        callback: function () {
          if ($scope.selection.node == null) {
            $scope.selection.node = $scope.nodes[$scope.nodes.length - 1];
            return;
          };


          var nodeIndex = $scope.nodes.indexOf($scope.selection.node);
          if (nodeIndex < $scope.nodes.length - 1) {
            $scope.selection.node = $scope.nodes[nodeIndex + 1];
          }
        },
      })

      .add({
        combo: 'ctrl+x',
        description: 'Delete selected cell.',
        callback: function () {
          if ($scope.selection.node != null) {
            $scope.removeNode($scope.selection.node);
          };
        },
      })

      .add({
        combo: 'ctrl+enter',
        description: 'Edit/Submit selected cell.',
        callback: function () {
          var node = $scope.selection.node;

          if (node != null) {
            if (node.state == "edit") {
              $scope.renderNode(node);
            } else {
              $scope.editNode(node);
            };
          };
        },
      });


    // Add the shortcuts for the manuskript plugins.
    var plugins = $scope.listPlugins();
    for (var pluginName in plugins) {
      var item = plugins[pluginName];

      if (item.hotkey) {
        hotkeys.bindTo($scope).add({
          combo: "c " + item.hotkey,
          description: item.description,
          callback: function(event, hotkey) {
            event.preventDefault();

            for (var name in plugins) {
              if (hotkey.description == plugins[name].description) {
                $scope.addNode(null, name);
                return false;
              };
            }

            return false;
          }
        })
      };
    }

    // First time we run, we need to load the cells from the server.
    $scope.loadNodesFromServer();
  });

})();
