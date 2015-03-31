'use strict';
(function() {

  var module = angular.module('rekall.runplugin.rekallPagedTable.directive',
                              ['ui.bootstrap']);

  module.directive('rekallPagedTable', function() {
    return {
      restrict: 'E',
      scope: {
        collection: '=',
        headers: '=',
      },
      templateUrl: '/rekall-webconsole/components/runplugin/paged-table.html',
      link: function(scope, element, attrs) {
        scope.pageSize = 10;
        scope.rowGroups = [];
        scope.pageRows = [];
        scope.paginationSelectedPage = 1;
        scope.minimized = true;
        scope.totalPages = 0;

        scope.toggleMinimize = function() {
          scope.minimized = !scope.minimized;
        };

        scope.$watchCollection('collection', function(newCollection, oldCollection) {
          var currentGroup;
          if (scope.rowGroups.length > 0) {
            currentGroup = scope.rowGroups[scope.rowGroups.length - 1];
          } else {
            currentGroup = [];
          }

          var oldLength;
          if (oldCollection.length < newCollection.length) {
            oldLength = oldCollection.length;
          } else {
            oldLength = 0;
          }

          for (var i = oldLength; i < scope.collection.length; ++i) {
            var item = scope.collection[i];
            if (item.branch && item.depth === 0) {
              if (currentGroup.length > 0) {
                scope.rowGroups.push(currentGroup);
              }
              currentGroup = [item];
            } else if (item.depth > 0) {
              currentGroup.push(item);
            } else {
              if (currentGroup.length > 0) {
                scope.rowGroups.push(currentGroup);
              }
              scope.rowGroups.push([item]);
              currentGroup = [];
            }
          }

          if (currentGroup.length > 0) {
            scope.rowGroups.push(currentGroup);
          }
        });

        scope.$watchGroup(
          ['collection',
           'pageSize',
           'paginationSelectedPage'],
          function() {
            var pageNumber = scope.paginationSelectedPage - 1;
            scope.pageRows = [];

            var pageGroups = scope.rowGroups.slice(
              pageNumber * scope.pageSize, (pageNumber + 1) * scope.pageSize);
            for (var i = 0; i < pageGroups.length; ++i) {
              var pageGroup = pageGroups[i];
              scope.pageRows.push.apply(scope.pageRows, pageGroup);
            }

            scope.totalPages = parseInt(
              scope.rowGroups.length / scope.pageSize) + 1;
          });

        scope.$watch('minimized', function() {
          scope.pageSize = scope.minimized ? 5 : 50;
        });

        scope.selectPage = function(pageNumber) {
          if (pageNumber > 0 && pageNumber <= scope.totalPages) {
            scope.paginationSelectedPage = pageNumber;
          };
        }

        scope.toggleTreeNode = function(branchRow) {
          var rowIndex = -1;
          for (var i = 0; i < scope.pageRows.length; ++i) {
            if (scope.pageRows[i] === branchRow) {
              rowIndex = i;
              break;
            }
          }
          if (rowIndex == -1) {
            return;
          }

          branchRow.opened = !branchRow.opened;

          if (branchRow.opened) {
            var ignoreUntilDepth = 0;
            for (var i = rowIndex + 1; i < scope.pageRows.length; ++i) {
              var currentRow = scope.pageRows[i];

              if (currentRow.depth === branchRow.depth) {
                break;
              }
              if (ignoreUntilDepth > 0) {
                if (currentRow.depth > ignoreUntilDepth) {
                  continue;
                } else {
                  ignoreUntilDepth = 0;
                }
              }
              if (currentRow.branch && !currentRow.opened) {
                ignoreUntilDepth = currentRow.depth;
              }
              currentRow.visible = true;
            }
          } else {
            for (var i = rowIndex + 1; i < scope.pageRows.length; ++i) {
              var currentRow = scope.pageRows[i];

              if (currentRow.depth > branchRow.depth) {
                currentRow.visible = false;
              } else {
                break;
              }
            }
          }
        };
      }
    };
  });
})();
