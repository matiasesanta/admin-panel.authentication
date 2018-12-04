angular.module('adminPanel.authentication').service('UserService', [
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

            var serverExpirationTime = new Date(jwtPayload.exp * 1000);
            var clientExpirationTime = new Date((jwtPayload.iat + object.maxSessionTime) * 1000);
            
            UserFactory.setData(jwtPayload);

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
            
            UserFactory.setData(jwtPayload);
            return jwtPayload;
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
