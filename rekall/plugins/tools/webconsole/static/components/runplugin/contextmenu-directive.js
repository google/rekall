'use strict';
(function() {

  var module = angular.module('rekall.runplugin.contextMenu.directive', []);

  module.directive('rekallContextMenu', function() {
    return {
      restrict: 'E',
      transclude: true,
      controller: function($scope) {
        var menu = $scope.menu = {
          'items': [],
          'visible': true,
          'style': {
            'left': 0,
            'top': 0
          }
        };

        this.showContextMenu = function(newMenuItems, x, y) {
          $scope.$apply(function () {
            menu.items = newMenuItems;
            menu.visible = true;
            menu.style.left = x;
            menu.style.top = y;
          });
        };

        this.hideContextMenu = function() {
          $scope.$apply(function () {
            menu.visible = false;
          });
        };

        $scope.callItem = function(item, event) {
          item.action($scope);
          event.stopPropagation();
          menu.visible = false;
        };
      },
      link: function(scope , element, attrs) {  // jshint ignore:line
        var documentClickHandler = function(event) {  // jshint ignore:line
          if (!scope.menu.visible) {
            return;
          }

          scope.menu.visible = false;
        };

        $(document).bind('click', documentClickHandler);
        scope.$on('$destroy', function() {
          $(document).unbind('click', documentClickHandler);
        });
      },
      templateUrl: '/rekall-webconsole/components/runplugin/contextmenu.html',
    };
  });
})();
