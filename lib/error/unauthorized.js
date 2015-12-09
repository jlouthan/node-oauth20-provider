var
    util = require('util'),
    oauth2 = require('./oauth2.js');

var unauthorized = function (msg) {
    unauthorized.super_.call(this, 'unauthorized', msg, 401, this.constructor);
};
util.inherits(unauthorized, oauth2);
unauthorized.prototype.name = 'OAuth2UnauthorizedRequest';
unauthorized.prototype.logLevel = 'info';

module.exports = unauthorized;