'use strict';

var loadSample = function(sampleName) {
  var request = new XMLHttpRequest();

  // 'false' makes the request synchronous
  request.open('GET', "base/tests/data/" + sampleName + '.json', false);
  request.send(null);

  if (request.status === 200) {
    return JSON.parse(request.responseText);
  } else {
    throw "Can't load sample: " + sampleName;
  }
}

var nothingSample = loadSample("Nothing");
var oneRowTable = loadSample("OneRowTable");
var unnamedSection = loadSample("UnnamedSection");
var namedSection = loadSample("NamedSection");

describe('rekallJsonRendererService injection', function() {
  beforeEach(module('rekall.runplugin.jsonRenderer.service'));

  it('should contain an rekallJsonRendererService service', inject(function(rekallJsonRendererService) {
    expect(rekallJsonRendererService).not.toEqual(null);
  }));

});

describe('rekallJsonRendererService parsing', function() {
  beforeEach(module('rekall.runplugin.jsonRenderer.service'));

  var state;

  beforeEach(inject(function(rekallJsonRendererService) {
    state = rekallJsonRendererService.createEmptyState();
  }));

  it('parses empty sample into metadata and no elements', inject(function(rekallJsonRendererService) {
    rekallJsonRendererService.parse(nothingSample, state);
    expect(state.metadata.tool_name).toEqual('rekall');
    expect(state.metadata.plugin_name).toEqual('render_sample');
    expect(state.elements).toEqual([]);
  }));

  it('parses single row table into table element', inject(function(rekallJsonRendererService) {
    rekallJsonRendererService.parse(oneRowTable, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type: 'table',
      header: {
	columns: [[ 'Parameter', 'parameter', '30' ],
		  [ ' Documentation', 'doc', '70' ]]
      },
      rows : [['important-parameter', 42 ]]
    });
  }));

  it('parses unnamed section into unnamed section element', inject(function(rekallJsonRendererService) {
    rekallJsonRendererService.parse(unnamedSection, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type: 'section'
    });
  }));

  it('parses named section into named section element', inject(function(rekallJsonRendererService) {
    rekallJsonRendererService.parse(namedSection, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type: 'section',
      name: 'Named Section'
    });
  }));
});
