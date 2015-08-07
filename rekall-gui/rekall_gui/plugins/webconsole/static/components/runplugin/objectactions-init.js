'use strict';
(function() {

  var module = angular.module('rekall.runplugin.objectActions.init',
			      ['rekall.runplugin.objectActions.service',
                               'ui.bootstrap']);

  module.run(function(rekallObjectActionsService, $modal) {
    // No popup for these.
    rekallObjectActionsService.registerHandler('NativeType', function(obj) {
      return [];
    });

    rekallObjectActionsService.registerHandler('BaseObject', function(obj) {
      return [
        {
          title: 'HexDump',
          description: 'View HexDump',
          action: function($scope) {
            rekallObjectActionsService.createNewRekallModal($scope, "dump", {
              address_space: obj.vm,
              offset: obj.offset,
            });
          },
        },
        {
          title: 'Disassemble',
          description: 'Disassemble',
          action: function($scope) {
            rekallObjectActionsService.createNewRekallModal($scope, "dis", {
              address_space: obj.vm,
              offset: obj.offset,
            });
          },
        },
      ];;
    });

    rekallObjectActionsService.registerHandler('Address', function(obj) {
      return [
        {
          title: 'HexDump',
          description: 'View HexDump',
          action: function($scope) {
            rekallObjectActionsService.createNewRekallModal($scope, "dump", {
              offset: obj.value,
            });
          },
        },
        {
          title: 'Disassemble',
          description: 'Disassemble',
          action: function($scope) {
            rekallObjectActionsService.createNewRekallModal($scope, "dis", {
              offset: obj.value,
            });
          },
        },
      ];;
    });


    rekallObjectActionsService.registerHandler('Struct', function(obj) {

      // Append new actions to the BaseObject's actions.
      return rekallObjectActionsService.menuItemsForObjectWithType(
        obj, "BaseObject").concat([
          {
            title: 'Struct',
            description: 'View Struct members',
            action: function($scope) {
              rekallObjectActionsService.createNewRekallModal($scope, "dt", {
                address_space: obj.vm,
                offset: obj.offset,
                target: obj.type_name
              });
            },
          },
        ]);
    });

    rekallObjectActionsService.registerHandler('_EPROCESS', function(obj) {
      return rekallObjectActionsService.menuItemsForObjectWithType(
        obj, "Struct").concat([
          {
            title: "Information",
            description: "Show process information",
            action: function($scope) {
              var new_scope = $scope.$new(true);
              new_scope.object = obj;
              $modal.open({
                templateUrl: '/rekall-webconsole/components/runplugin/templates/eprocess.html',
                scope: new_scope,
              });
            }
          },

          {
            title: 'Vad',
            description: 'View Process VAD',
            action: function($scope) {
              rekallObjectActionsService.createNewRekallCell($scope, "vad", {
                eprocess: obj.offset,
              });
            },
          },

          {
            title: 'Process Info',
            description: 'View Process Info',
            action: function($scope) {
              rekallObjectActionsService.createNewRekallCell($scope, "procinfo", {
                eprocess: obj.offset,
              });
            },
          },

        ]);
    });

    // Pointers' context menu open their target objects's context menu instead.
    rekallObjectActionsService.registerHandler('Pointer', function(obj) {
      var target_obj = obj.target_obj;
      var actions = [];

      // Append the target's menu actions to this menu.
      if (target_obj) {
        actions = rekallObjectActionsService.menuItemsForObject(target_obj);
      };

      if (actions.length === 0) {
        return [
          {
            title: 'HexDump',
            description: 'View HexDump',
            action: function($scope) {
              rekallObjectActionsService.createNewRekallModal($scope, "dump", {
                address_space: obj.vm,
                offset: obj.target,
              });
            },
          },
        ];
      } else {
        return actions;
      };
    });
  });

})();
