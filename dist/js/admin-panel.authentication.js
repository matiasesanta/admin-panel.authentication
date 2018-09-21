
angular.module('adminPanel.authentication', [
    'ngStorage',
    'ngRoute',
    'adminPanel'
]).config(['$routeProvider', function($routeProvider) {
        $routeProvider.
            when('/login', {});
}]).config(['$httpProvider', function($httpProvider) {
    $httpProvider.interceptors.push('AuthenticationInterceptor');
}]);;angular.module('adminPanel.authentication').directive('apUser',[
    'AuthenticationService', '$location', function(AuthenticationService, $location) {
        return {
            restrict: 'A',
            transclude: true,
            link: function(scope) {
                function chekIfUserLogged() {
                    scope.user = AuthenticationService.checkLogin();
                    if(scope.user && $location.path() === '/login') {
                        $location.path('/');
                    }
                }

                function sendUserData() {
                    angular.element(document).ready(function () {
                        scope.$broadcast('userData', scope.user);
                    });
                }

                chekIfUserLogged();

                scope.$on('$routeChangeStart', function() {
                    chekIfUserLogged();
                    sendUserData();
                });
            },
            templateUrl: 'directive/user.template.html'
        };
    }
]);;function loginFormController($scope, $location, AuthenticationService) {
    $scope.username = '';
    $scope.password = '';
    $scope.error = '';
    
    $scope.submit = function() {
        $scope.error = '';
        if($scope.form.$valid) {
            $scope.$emit('apLoad:start');
            AuthenticationService.login($scope.username, $scope.password, function (result) {
                $scope.$emit('apLoad:finish');
                if (result === true) {
                    $location.path('/');
                } else {
                    $scope.error = 'Usuario o contraseña incorrectos';
                }
            });
        }
    };
 
    this.$onInit = function() {
        // reset login status
        if(!AuthenticationService.checkLogin()) {
            AuthenticationService.logout();
        }
    };
    
    this.$postLink = function() {
        $('login-form').foundation();
    };
}

angular.module('adminPanel.authentication').component('loginForm', {
    templateUrl: 'login-form/login-form.template.html',
    controller: ['$scope','$location', 'AuthenticationService', loginFormController]
});;function loginController($scope) {
    
    this.$postLink = function() {
        $('login').foundation();
    };
}

angular.module('adminPanel.authentication').component('login', {
    templateUrl: 'login/login.template.html',
    controller: ['$scope', loginController]
});;angular.module('adminPanel.authentication').factory('AuthenticationInterceptor',[
    '$q', '$location', 'UserService', 'FirewallService', function($q, $location, User, Firewall) {
        function redirectLogin() {
            if($location.path() !== '/login') {
                $location.path('/login');
            }
        }
        
        return {
            request: function(config) {
                User.setLogged(null);
                var isAllowedPath = Firewall.isAllowedPath($location.path());
                if(isAllowedPath) {
                    User.setLogged(true);
                    return config;
                }
                if(!config.headers.Authorization) {
                    if(User.isLogged()) {
                        config.headers.Authorization = 'Bearer ' + User.getToken();
                    } else {
                        redirectLogin();
                    }
                }
                return config;
            },
            responseError: function (response) {
                if (response.status === 401){
                    User.logout();
                    redirectLogin();
                }
                return $q.reject(response);
            }
        };
    }
]);
;angular.module('adminPanel.authentication').provider('AuthenticationService', function() {
    var excludePaths = ['/login'];
    var apiPath = null;
    var maxSessionTime = 3600;
    var debugMode = false;

    this.setApiPath = function(path) {
        if(!(path instanceof String) && typeof(path) !== 'string') {
            throw 'The path must be a String.';
        }
        apiPath = path;

        return this;
    };
    this.excludePaths = function(paths) {
        if(!(paths instanceof Array)) {
            throw 'The paths must be an Array of Regex';
        }
        excludePaths = paths;

        return this;
    };
    this.setMaxSessionTime = function(time) {
        if(!(time instanceof Number) && typeof(time) !== 'number') {
            throw 'The time must be numeric';
        }
        maxSessionTime = time;

        return this;
    };
    this.enableDebugMode = function () {
        debugMode = true;

        return this;
    };


    this.$get = [
        '$http', 'UserService', 'FirewallService',
        function($http, User, Firewall) {
            if(apiPath === null) {
                throw 'The path must be initialized.';
            }

            if(debugMode) {
                Firewall.setExcludePaths([/^./]);
            } else {
                Firewall.setExcludePaths(excludePaths);
            }

            return {
                login: Login,
                logout: Logout,
                checkLogin: checkLogin
            };

            function checkLogin() {
                if(User.isLogged()) {
                    $http.defaults.headers.common.Authorization = 'Bearer ' + User.getToken();
                    return User.getUserData();
                }
                return null;
            }

            function Login(username, password, callback) {
                var promise = $http.post(apiPath + '/login', { _username: username, _password: password });
                promise.then(function (response) {
                    if (response.data && response.data.token) {
                        User.login({
                            token: response.data.token,
                            maxSessionTime: maxSessionTime,
                            excludePaths: excludePaths
                        });

                        $http.defaults.headers.common.Authorization = 'Bearer ' + response.data.token;

                        callback(true);
                    } else {
                        callback(false);
                    }
                }, function(error) {
                    callback(false, error);
                });
            }

            function Logout() {
                User.logout();
                $http.defaults.headers.common.Authorization = '';
            }
        }
    ];

});;angular.module('adminPanel.authentication').service('FirewallService', [
    function() {
        //Por defecto estan habilitadas todas las rutas.
        var excludePaths = [/^./];
        
        var checkPaths = function(path) {
            for(var i = 0; i < excludePaths.length; i++) {
                if(path.match(excludePaths[i])) {
                    return true;
                }
            }
            return false;
        };
        
        this.setExcludePaths = function(paths) {
            excludePaths = paths;
        };
        
        this.isAllowedPath = function (path) {
            if(excludePaths !== null) {
                var ret = checkPaths(path);
                return ret;
            }
            return false;
        };
    }
]);
;angular.module('adminPanel.authentication').service('TokenParserService', [
    function() {

        this.parseJwt = function(token) {
            try {
                var base64Url = token.split('.')[1];
                var base64 = base64Url.replace('-', '+').replace('_', '/');
                var data = JSON.parse(window.atob(base64));
                if (!data.username) {
                    throw 'The token does not contain username in payload';
                }
                if (!data.exp) {
                    throw 'The token does not contain exp in payload';
                }
                if (!data.iat) {
                    throw 'The token does not contain iat in payload';
                }
                return data;
            } catch(err) {
                console.error(err);
                throw 'Token decoding error';
            }
        };
    }
]);
;angular.module('adminPanel.authentication').factory('UserFactory', function() {
        return {
            data: null,

            setData: function(value) {
                this.data = {
                    username: value.username || '',
                    roles: value.roles || null
                };
            },

            getData: function() {
                return this.data;
            },

            deleteData: function() {
                this.data = null;
            }
        };
    }
);
;angular.module('adminPanel.authentication').service('UserService', [
    '$localStorage', 'UserFactory', 'TokenParserService',
    function($localStorage, UserFactory, TokenParserService) {
        var logged = false;
        this.login = login;
        this.initData = initData;
        this.logout = logout;
        this.getUserData = getUserData;
        this.getUsername = getUsername;
        this.getRoles = getRoles;
        this.isLogged = isLogged;
        this.setLogged = setLogged;
        this.getToken = getToken;
        this.setToken = setToken;
        this.isGranted = isGranted;

        function login (object) {

            var jwtPayload = TokenParserService.parseJwt(object.token);

            UserFactory.setData({
                username: jwtPayload.username,
                roles: jwtPayload.roles
            });

            var serverExpirationTime = new Date(jwtPayload.exp * 1000);
            var clientExpirationTime = new Date((jwtPayload.iat + object.maxSessionTime) * 1000);
            $localStorage.session = {
                access_token: object.token,
                exp: Math.min(clientExpirationTime, serverExpirationTime),
                excludePaths: object.excludePaths
            };
        }

        function initData() {
            var token = this.getToken();
            if (!token) {
                return null;
            }
            var jwtPayload = TokenParserService.parseJwt(token);
            var data = {
                username: jwtPayload.username,
                roles: jwtPayload.roles
            };
            UserFactory.setData(data);
            return data;
        }

        function logout() {
            if ($localStorage.session) {
                delete $localStorage.session;
            }
            UserFactory.deleteData();
        }

        function getUserData() {
            var data = UserFactory.getData();
            if (!data) {
                data = this.initData();
            }
            return data;
        }

        function getUsername() {
            var data = this.getUserData();
            if (!data) {
                return null;
            }
            return data.username;
        }

        function getRoles() {
            var data = this.getUserData();
            if (!data) {
                return null;
            }
            return data.roles;
        }

        function setLogged(val) {
            logged = val;
        }

        function isLogged() {
            if(logged === true) return true;

            var now = new Date().getTime();
            if($localStorage.session && now < $localStorage.session.exp) {
                return true;
            }

            logout();
            return false;
        }

        function getToken() {
            if($localStorage.session) {
                return $localStorage.session.access_token;
            }
            return '';
        }

        function setToken(token) {
            if(!$localStorage.session) {
                return false;
            }
            $localStorage.session.access_token = token;

            return true;
        }

        function isGranted(role) {
            if($localStorage.session && $localStorage.session.roles) {
                return $localStorage.session.roles.indexOf(role) !== -1;
            }
            return false;
        }
    }
]);
;angular.module('adminPanel.authentication').run(['$templateCache', function ($templateCache) {
  $templateCache.put("directive/user.template.html",
    "<div ng-if=!user><login></login></div><div ng-if=user ng-transclude></div>");
  $templateCache.put("login-form/login-form.template.html",
    "<form name=form ng-submit=submit() data-abide novalidate><div ng-if=error class=\"alert callout\"><p><i class=\"fa fa-warning\"></i><span ng-bind=error></span></p></div><label>Usuario<div class=input-group><span class=input-group-label><i class=\"fas fa-user\" aria-hidden=true></i></span><input class=input-group-field name=username type=text ng-model=username required></div><span class=form-error>El usuario es requerido</span></label><label>Contraseña<div class=input-group><span class=input-group-label><i class=\"fa fa-lock\" aria-hidden=true></i></span><input class=input-group-field name=password type=password ng-model=password required></div><span class=form-error>La contraseña es requerida</span></label><div class=row><input type=submit class=button value=Ingresar></div></form>");
  $templateCache.put("login/login.template.html",
    "<div class=container><ap-box class=login-form title=Login init=init()><login-form></login-form></ap-box></div>");
}]);
