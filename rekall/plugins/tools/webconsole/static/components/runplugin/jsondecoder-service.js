'use strict';
(function() {

  var module = angular.module('rekall.runplugin.jsonDecoder.service', []);

  var serviceImplementation = function($http) {

    var decode = function(item, state) {
      if (item instanceof Array) {
        if (item.length === 2 && item[0] === '*') {
          return item[1];
        } else if (item.length ===2 && item[0] === '+') {
          return atob(item[1]);
        } else {
          var decoded = [];
          for (var i = 0; i < item.length; ++i) {
            decoded.push(decode(item[i], state));
          }
          return decoded;
        }
      } else if (item instanceof Object) {
        var data = {
          session_id: state.session_id,
        };
        for (var key in item) {
          var value = item[key];

          var decodedKey = decode(key, state);
          var decodedValue = decode(value, state);

          data[decodedKey] = decodedValue;
        }
        return data;
      } else {
        return item;
      }
    };

    // Handlers map
    var metadataHandler = function(data, state) {
      if (data.length !== 1) {
        throw 'Invalid metadata data.';
      }

      state.metadata = data[0];
      if (angular.isUndefined(state.metadata.session)) {
        state.session_id = 0;
      } else {
        state.session_id = state.metadata.session.session_id;
      };
    };

    var sectionHandler = function(data, state) {
      if (data.length !== 1) {
        throw 'Invalid section data.';
      }
      data = data[0];

      var sectionData = {type: 'section'};

      data = decode(data, state);
      if (typeof(data['name']) === 'string') {
        sectionData['name'] = data['name'];
      }

      state.elements.push(sectionData);
    };

    var freeFormatHandler = function(data, state) {
      var decodedData = [];
      var renderedData = [];
      for (var i = 0; i < data.length; ++i) {
        var decodedValue = decode(data[i], state);
        decodedData.push(decodedValue);
      }

      state.elements.push({type: 'format', data: decodedData});
    };

    var errorHandler = function(data, state) {
      if (data.length !== 1) {
        throw 'Invalid free format data.';
      }

      state.elements.push({type: 'error', data: decode(data[0], state)});
    };

    var tableHandler = function(data, state) {
      if (data.length !== 2) {
        throw 'Invalid table data.';
      }

      var header = data[0];
      var options = data[1];

      state.elements.push({type: 'table',
                           header: header,
                           options: options,
                           rows: []});
    };

    var rowHandler = function(data, state) {
      data = data[0];

      var i;
      var lastElement;
      for (i = state.elements.length - 1; i >= 0; --i) {
        if (state.elements[i].type === 'table') {
          lastElement = state.elements[i];
          break;
        }
      }

      if (lastElement === undefined) {
        throw 'Inconsistent state.';
      }

      var row = [];
      for (i = 0; i < lastElement.header.length; ++i) {
        var column = lastElement.header[i];

        var columnName = column.cname || column.name;
        var columnData = data[columnName];

        // TODO(mbushkov): Ideally, all elements should have mro set and we
        // should be able to render them based solely on their type.
        if (columnData == undefined) {
          columnData = {mro: 'None'};

        } else if (column.formatstring === '[addr]' &&
                   columnData.mro === undefined) {
          columnData = {mro: 'Address',
                        value: columnData};
        } else if (column.formatstring === '[addrpad]' &&
                   columnData.mro === undefined) {
          columnData = {mro: 'PaddedAddress',
                        value: columnData};
        }

        var decodedData = decode(columnData, state);
        var column_data = {
          data: decodedData,
        };

        // Special modeling of tree-table nodes.
        if (column.type == "TreeNode") {
          column_data.tree = true;
        };

        row.push(column_data);
      }

      var row_metadata = {
        data: row,
        count: lastElement.rows.length,
        depth: data.depth,
        visible: true,
      };

      if (data.depth !== undefined) {
        // Is this part of the tree opened?
        row_metadata.opened = false;

        // Only show the top level by default.
        if (data.depth > 0) {
          row_metadata.visible = false;
        };
      };

      // We can decide if the last row was a branch or a leaf now.
      if (lastElement.rows.length > 0) {
        var previous_row = lastElement.rows[lastElement.rows.length-1];

        if (row_metadata.depth > previous_row.depth) {
          previous_row.branch = true;
        };
      };

      lastElement.rows.push(row_metadata);
    };

    var progressHandler = function(data, state) {
      if (data.length !== 1) {
        throw 'Invalid progress data.';
      }

      state.progress = data[0];
    };

    var endHandler = function(data, state) {
      state.finished = true;
    };

    var fileHandler = function(data, state) {
      if (state.filenames == null) {
        state.filenames = [];
      }

      state.filenames.push(data[0]);
    };

    var handlersMap = {
      'm': metadataHandler,
      's': sectionHandler,
      'f': freeFormatHandler,
      'file': fileHandler,
      'e': errorHandler,
      't': tableHandler,
      'r': rowHandler,
      'p': progressHandler,
      'x': endHandler,
    };

    this.createEmptyState = function() {
      return {
        finished: false,
        elements: [],
        progress: 'Loading...'
      };
    };

    this.decode = function(data, state) {
      for (var i = 0; i < data.length; ++i) {
        var statement = data[i];
        var command = statement[0];

        if (handlersMap[command] !== undefined) {
          handlersMap[command](statement.slice(1), state);
        }
      }
    };
  };

  module.service('rekallJsonDecoderService', serviceImplementation);
})();
