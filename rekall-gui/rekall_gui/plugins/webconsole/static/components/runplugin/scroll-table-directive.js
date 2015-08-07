'use strict';
(function() {

  var module = angular.module('rekall.runplugin.rekallTable.directive',
                              ['rekall.runplugin.tableCell.directive',
                               'ui.bootstrap']);

  module.directive('scrollTable', function($timeout, $rootScope) {
    return {
      restrict: 'E',
      scope: {
        collection: '=',
        headers: '=',
        height: '=',
        session_id: '=',
      },

      templateUrl: '/rekall-webconsole/components/runplugin/scroll-table.html',
      link: function($scope, element, attrs) {
        $scope.start_row = 0;
        $scope.end_row = 1;
        $scope.window = $scope.end_row - $scope.start_row;
        $scope.rows = []

        // The actual pane which will scroll.
        var scroll_pane = element.find(".infinite-scroll");

        // Copy from start_row to end_row from the collection to the rows
        // variable for rendering.
        var updateRows = function() {
          if ($scope.rows.length >= $scope.collection.length) {
            return false
          };

          $scope.rows = $scope.collection.slice(
            $scope.start_row, $scope.end_row);
          return true
        };

        var shouldAdjustScroll = function() {
          var last_row = scroll_pane.find('tr').filter(':last');
          if (!last_row) {
            return;
          };

          var last_row_offset = last_row.offset();
          if (!last_row_offset) return;

          // Calculate the bottom of the scrolled area relative to the page.
          var bottom = (scroll_pane.scrollTop() +     // How many pixels of the
                                                      // inner table are hidden
                                                      // off the top of the
                                                      // scrolled pane.
                        scroll_pane[0].offsetHeight + // The height of the
                                                      // scrolled pane.
                        scroll_pane.offset().top);    // The top of the scrolled
                                                      // pane in the page.

          // Last row is visible.
          return last_row_offset.top < bottom;
        };

        // Check if the last row in the table is within the view port.
        var adjustScroll = function (done_callback, increment) {
          if(shouldAdjustScroll()) {
            $scope.end_row += increment || 1;

            // The a row was added, tell angular to check this table later to
            // see if we need to add more rows.
            if(updateRows()) {
              $timeout(function() {
                adjustScroll(done_callback, increment);
              });
            } else if (done_callback !== undefined) {
              done_callback();
            };
          };
        };

        scroll_pane.bind('scroll', function () {
          adjustScroll();
        });

        $scope.$watch('collection.length', function() {
          scroll_pane.scroll();
        });

        var updateHeight = function(height) {
          if (height === undefined) {
            return;
          }

          var container = element.find(".infinite-scroll");

          container.css({height: height + "px"});
          adjustScroll(function() {
            // Table is still too small for scroll area.
            var table_height = container.find("table").height();
            if (table_height < height) {
              container.css({height: table_height + "px"}).scroll();
            };
          }, 5)
        };

        $scope.minimized = true;
        $scope.minimizeToggle = function($event) {
          var button = $($event.target);
          button.toggleClass("minimized");
          if ($scope.minimized) {
            updateHeight(500);
          } else {
            updateHeight(120);
          };
          $scope.minimized = !$scope.minimized;

          $event.stopPropagation();
        };

        // Watch the height scope variable and adjust the table accordingly.
        $scope.$watch("height", updateHeight);

        $scope.toggleTreeNode = function(row) {
          row.opened = !row.opened;

          // Update visibility for direct children
          for (var i=row.count+1; i<$scope.collection.length; i++) {
            var tested_row = $scope.collection[i];

            // Opening a new branch - only show direct children.
            if (row.opened && tested_row.depth == row.depth + 1) {
                tested_row.visible = true;

            // Closing a branch - hide all deeper nodes.
            } else if (tested_row.depth > row.depth) {
                tested_row.visible = false
            };

            // If this row is shallower that the current row we can stop.
            if (tested_row.depth <= row.depth) {
              break;
            };
          };

          // If we close the tree we might need to expose some more rows in the
          // table.
          $timeout(adjustScroll);

          return false;
        };
      },
    };
  });

})();
