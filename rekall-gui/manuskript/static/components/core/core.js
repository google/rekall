(function() {
  var module = angular.module('manuskript.core', [
    'manuskript.core.network.service',
    'manuskript.core.nodePluginRegistry.service',
    'manuskript.core.addNodeDialog.controller',
    'manuskript.core.codeEditor.directive',
    'manuskript.core.fastRepeat.directive',
    'manuskript.core.fileInput.directive',
    'manuskript.core.fileInput.directive',
    'manuskript.core.fileSelector.controller',
    'manuskript.core.onAltEnter.directive',
    'manuskript.core.scrollTo.directive',
    'manuskript.core.splitList.directive',
  ]);
})();