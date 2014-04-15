var path = require('path');

module.exports = function(grunt) {
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      files: ['*.js', 'components/**/*.js'],
      options: {
        jshintrc: true,
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-jshint');

  grunt.registerTask('test', 'Run unit, docs and e2e tests with Karma', ['jshint']);
}
