angular.module('adminPanel.authentication').factory('UserFactory', function() {
        return {
            data: null,

            setData: function(data) {
                var newData = angular.copy(data);
                if (newData.exp) {
                    delete newData.exp;
                }
                if (newData.iat) {
                    delete newData.iat;
                }
                if (!newData.username) {
                    newData.username = '';
                }
                if (!newData.roles) {
                    newData.roles = null;
                }
                this.data = newData;
                return this.data;
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
