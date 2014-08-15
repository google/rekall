'use strict';

var loadSample = function(sampleName) {
  var request = new XMLHttpRequest();

  // 'false' makes the request synchronous
  request.open('GET', 'base/tests/data/' + sampleName + '.json', false);
  request.send(null);

  if (request.status === 200) {
    return JSON.parse(request.responseText);
  } else {
    throw 'Can not load sample: ' + sampleName;
  }
};

var nothingSample = loadSample('Nothing');
var oneRowTable = loadSample('OneRowTable');
var unnamedSection = loadSample('UnnamedSection');
var namedSection = loadSample('NamedSection');

describe('rekallJsonDecoderService injection', function() {
  beforeEach(module('rekall.runplugin.jsonDecoder.service'));

  it('should contain an rekallJsonDecoderService service', inject(function(rekallJsonDecoderService) {
    expect(rekallJsonDecoderService).not.toEqual(null);
  }));

});

describe('rekallJsonDecoderService decoding', function() {
  beforeEach(module('rekall.runplugin.jsonDecoder.service'));

  var state;

  beforeEach(inject(function(rekallJsonDecoderService) {
    state = rekallJsonDecoderService.createEmptyState();
  }));

  it('decodes empty sample into metadata and no elements', inject(function(rekallJsonDecoderService) {
    rekallJsonDecoderService.decode(nothingSample, state);
    expect(state.metadata.tool_name).toEqual('rekall');  // jshint ignore:line
    expect(state.metadata.plugin_name).toEqual('render_sample');  // jshint ignore:line
    expect(state.elements).toEqual([]);
  }));

  it('decodes single row table into table element', inject(function(rekallJsonDecoderService) {
    rekallJsonDecoderService.decode(oneRowTable, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type : 'table',
      header : [{cname: 'parameter',
		 name: 'Parameter',
		 formatstring : '30'},
		{cname: 'doc',
		 name: ' Documentation',
		 formatstring: '70'}],
      options: {},
      rows : [
	[{data: 'important-parameter', rendered: 'important-parameter' },
	 {data: 42, rendered : '42'}]]
    });
  }));

  it('decodes unnamed section into unnamed section element', inject(function(rekallJsonDecoderService) {
    rekallJsonDecoderService.decode(unnamedSection, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type: 'section'
    });
  }));

  it('decodes named section into named section element', inject(function(rekallJsonDecoderService) {
    rekallJsonDecoderService.decode(namedSection, state);
    expect(state.elements.length).toEqual(1);
    expect(state.elements[0]).toEqual({
      type: 'section',
      name: 'Named Section'
    });
  }));
});
