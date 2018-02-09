angular.module('adminPanel.authentication').directive('apUser',[
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
]);