(function() {
  angular.module('manuskript.core', [
    'manuskript.core.nodePluginRegistry.service',
    'manuskript.core.addNodeDialog.controller',
    'manuskript.core.codeEditor.directive',
    'manuskript.core.fileInput.directive',
    'manuskript.core.onAltEnter.directive',
    'manuskript.core.scrollTo.directive',
    'manuskript.core.splitList.directive',
  ]);
})();