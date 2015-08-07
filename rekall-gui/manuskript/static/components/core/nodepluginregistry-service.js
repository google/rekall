(function() {

  var module = angular.module('manuskript.core.nodePluginRegistry.service', []);

  /**
   * Implementation of the manuskriptCoreNodePluginRegistryService. This
   * service maintains a list of all registered Manuskript plugins.
   */
  var serviceImplementation = function() {
    /**
     * Dictionary of registered plugins.
     */
    this.plugins = {};

    /**
     * Register a plugin with a given name and descriptor.
     * @param {string} pluginName - Name of the plugin to register.
     * @param {object} pluginDescriptor - Descriptor dictionary for the plugin.
     */
    this.registerPlugin = function(pluginName, pluginDescriptor) {
      this.plugins[pluginName] = pluginDescriptor;
    };

    /**
     * @returns A dictionary of all registered plugins.
     */
    this.getAllPlugins = function() {
      return this.plugins;
    };

    /**
     * Returns default node for a given plugin.
     * @param {string} pluginName - Name of the plugin whose default node is
     *                 required.
     * @returns {object} A default node for a given plugin.
     */
    this.createDefaultNodeForPlugin = function(pluginName) {
      var plugin = this.plugins[pluginName];
      var node = plugin.defaultNode();

      // Each node has a unique ID.
      node.id = Date.now();
      return node;
    };

    /**
     * @returns {object} Plugin descriptor for a plugin with a given name.
     */
    this.getPlugin = function(pluginName) {
      return this.plugins[pluginName];
    };
  };

  module.service('manuskriptCoreNodePluginRegistryService', serviceImplementation);
})();
