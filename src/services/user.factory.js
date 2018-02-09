angular.module('adminPanel.authentication').factory('UserFactory', function() {
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
