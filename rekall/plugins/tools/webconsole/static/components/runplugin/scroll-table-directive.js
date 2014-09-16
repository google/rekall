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
          var bottom = (scroll_pane.scrollTop() +     // How many pixels of the inner
                                                      // table are hidden off the top
                                                      // of the scrolled pane.
                        scroll_pane[0].offsetHeight + // The height of the scrolled pane.
                        scroll_pane.offset().top);    // The top of the scrolled pane in
                                                      // the page.

          // Last row is visible.
          return last_row_offset.top < bottom;
        };

        // Check if the last row in the table is within the
        var adjustScroll = function (done_callback) {
          if(shouldAdjustScroll()) {
            $scope.end_row +=1;

            // The a row was added, tell angular to check this table later to
            // see if we need to add more rows.
            if(updateRows()) {
              $timeout(function() {
                adjustScroll();
              });
            } else if (done_callback !== undefined) {
              done_callback();
            };
          };
        };

        scroll_pane.bind('scroll', function () {
          adjustScroll();
        });

        $scope.$watch('collection', function() {
          scroll_pane.scroll();
        });

        // Watch the height scope variable and adjust the table accordingly.
        $scope.$watch("height", function(height) {
          var container = $(element).find(".infinite-scroll");

          container.css({height: height + "px"});
          adjustScroll(function() {
            // Table is still too small for scroll area.
            var table_height = container.find("table").height();
            if (table_height < height) {
              container.css({height: table_height + "px"}).scroll();
            };
          });
        });
      },
    };
  });

})();