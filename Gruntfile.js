
module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        bower: {
            install: {
                options: {
                    install: true,
                    copy: false,
                    targetDir: './lib',
                    cleanTargetDir: true
                }
            }
        },
        jshint: {
            all: ['Gruntfile.js', 'src/*.js', 'src/**/*.js']
        },
        html2js: {
            dist: {
                src: ['src/**/*.html'],
                dest: 'tmp/templates.js'
            }
        },
        concat: {
            options: {
                separator: ';'
            },
            dist: {
                src: ['src/**/*.js', 'tmp/*.js'],
                dest: 'dist/js/admin-panel.authentication.js'
            }
        },
        clean: {
            temp: {
                src: ['tmp']
            }
        },
        uglify: {
            options: {
                banner: '/*! <%= pkg.name %> <%= grunt.template.today("yyyy-mm-dd") %> */\n'
            },
            build: {
                src: 'src/<%= pkg.name %>.js',
                dest: 'dist/<%= pkg.name %>.min.js'
            },
            dist: {
                files: {
                    'dist/js/admin-panel.authentication.min.js': ['dist/js/admin-panel.authentication.js']
                }
//                options: {
//                    mangle: false
//                }
            }
        },
        watch: {
            dev: {
                files: ['Gruntfile.js', 'src/**/*.js', '*.html'],
                tasks: ['jshint', 'html2js:dist', 'concat:dist', 'clean:temp'],
                options: {
                    atBegin: true
                }
            },
            min: {
                files: ['Gruntfile.js', 'src/**/*.js', '*.html'],
                tasks: ['jshint', 'html2js:dist', 'concat:dist', 'clean:temp', 'uglify:dist'],
                options: {
                    atBegin: true
                }
            }
        },
        sass: {
            dist: {
                options: {
                    style: 'expanded'
                },
                files: {
                    'dist/css/admin-panel.authentication.css': 'src/authentication.style.scss'
                }
            }
        },
        cssmin: {
            dist: {
                files: {
                    'dist/css/admin-panel.authentication.min.css': 'dist/css/admin-panel.authentication.css'
                }
            }
        }
    });
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-html2js');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-bower-task');
    grunt.loadNpmTasks('grunt-contrib-sass');
    grunt.loadNpmTasks('grunt-contrib-cssmin');
    
    grunt.registerTask('dev', ['bower', 'connect:server', 'watch:dev']);
    grunt.registerTask('test', ['bower', 'jshint']);
    grunt.registerTask('minified', ['bower', 'watch:min']);
    grunt.registerTask('package', ['bower', 'jshint', 'html2js:dist', 'concat:dist', 'sass:dist', 'cssmin',
        'uglify:dist', 'clean:temp']);
};
