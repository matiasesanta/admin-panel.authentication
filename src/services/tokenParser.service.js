angular.module('adminPanel.authentication').service('TokenParserService', [
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
