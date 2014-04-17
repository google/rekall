(function() {
  angular.module('manuskript.core', [
    'manuskript.core.nodePluginRegistry.service',
    'manuskript.core.onAltEnter.directive',
    'manuskript.core.splitList.directive',
    'manuskript.core.codeEditor.directive',
    'manuskript.core.fileInput.directive']);
})();