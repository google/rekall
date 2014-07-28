(function() {

  var module = angular.module('rekall.runplugin.jsonRenderer.service', []);

  var decodeValue = function(value, state) {
    if (value === null) {
      return null;
    } else if (value instanceof Array) {
      if (value[0] == "_") {

	var decodedList = [];
	for (var i = 1; i < value.length; ++i) {
	  decodedList.push(decodeValue(value[i]))
	}
	return decodedList;

      } else if (value[0] == "+") {

	return atob(state.lexicon[value[1].toString()]);

      }
    } else if (value instanceof Object) {
      return decode(value, state);
    }

    result = state.lexicon[value.toString()];
    if (result === undefined) {
      throw 'Corrupt lexicon: ' + value + ' not found.';
    } else {
      return result;
    }
  };

  var decode = function(item, state) {
    if (item instanceof Array || !(item instanceof Object)) {
      return decodeValue(item, state);
    } else if (item["_"] !== undefined) {
      delete item["_"];

      var data = {};
      for (key in item) {
	var value = item[key];

	var decodedKey = decodeValue(key, state);
	var decodedValue = decodeValue(value, state);

	if (typeof(decodedValue) == 'object') {
	  decodedValue = decode(decodedValue, state);
	}

	data[decodedKey] = decodedValue;
      }

      return data;
    } else {
      return item;
    }

    return data;
  };

  // Handlers map
  var lexiconHandler = function(data, state) {
    state.lexicon = data;
  };

  var metadataHandler = function(data, state) {
    state.metadata = data;
  };

  var sectionHandler = function(data, state) {
    var sectionData = {type: 'section'};

    data = decode(data, state);
    if (typeof(data['name']) == 'string') {
      sectionData['name'] = data['name'];
    }

    state.elements.push(sectionData);
  };

  var freeFormatHandler = function(data, state) {
  };

  var errorHandler = function(data, state) {
    state.elements.push({type: "error", message: data});
  };

  var tableHandler = function(data, state) {
    state.elements.push({type: "table", header: data, rows: []});
  };

  var rowHandler = function(data, state) {
    var lastElement = undefined;
    for (var i = state.elements.length - 1; i >= 0; --i) {
      if (state.elements[i].type == "table") {
	lastElement = state.elements[i];
      }
    }

    if (lastElement === undefined) {
      throw "Inconsistent state.";
    }

    var row = [];

    for (var i = 0; i < lastElement.header.length; ++i) {
      var column = lastElement.header[i];
      var column_name = column.cname || column.name;
      row.push(data[column_name]);
    }
    lastElement.rows.push(row);
  };

  var handlersMap = {
    "l": lexiconHandler,
    "m": metadataHandler,
    "s": sectionHandler,
    "f": freeFormatHandler,
    "e": errorHandler,
    "t": tableHandler,
    "r": rowHandler
  };

  var serviceImplementation = function($http) {
    this.createEmptyState = function() {
      return {
        elements: [],
        metadata: {},
        lexicon: {}
      };
    };

    this.parse = function(data, state) {
      for (var i = 0; i < data.length; ++i) {
	var statement = data[i];
	var command = statement[0];

	if (handlersMap[command] !== undefined) {
	  handlersMap[command](statement[1], state);
	}
      }
    };

  };

  module.service('rekallJsonRendererService', serviceImplementation);
})();
