var
    query = require('querystring'),
    error = require('../error/'),
    emitter = require('./../events');
var Boom = require('boom');

function dataHapi(request, reply, code, data) {
    request.oauth2.logger.debug('Response: ', data);
    if (code >= 400) {
        var err = Boom.create(code)
        err.output.headers['Cache-Control'] = 'no-store';
        err.output.headers['Pragma'] = 'no-cache';
        err.output.payload.message = data.error_description;
        return reply(err);
    }
    else {
        var response = reply(data);
        response.statusCode = code;
        response.header('Cache-Control', 'no-store');
        response.header('Pragma','no-cache');
    }
}

function data(req, res, code, data) {
    if (typeof res === 'function') {
        return dataHapi(req, res, code, data);
    }
    res.statusCode = code;
    res.header('Cache-Control', 'no-store');
    res.header('Pragma','no-cache');
    res.send(data);
    req.oauth2.logger.debug('Response: ', data);
}

function redirectHapi(request, reply, redirectUri) {
    var response = reply();
    response.statusCode = 302;
    response.header('Location', redirectUri);
    request.oauth2.logger.debug('Redirect to: ', redirectUri);
}

function redirect(req, res, redirectUri) {
    if (typeof res === 'function') {
        return redirectHapi(req, res, redirectUri);
    }
    res.statusCode = 302;
    res.header('Location', redirectUri);
    res.end();
    req.oauth2.logger.debug('Redirect to: ', redirectUri);
}

module.exports.error = function(req, res, err, redirectUri) {
    // Transform unknown error
    if (!(err instanceof error.oauth2)) {
        req.oauth2.logger.error(err.stack);
        emitter.uncaught_exception(req, err);
        err = new error.serverError('Uncaught exception');
    }
    else {
        emitter.caught_exception(req, err);
        req.oauth2.logger[err.logLevel]('Exception caught', err.stack);
    }
        
    if (redirectUri) {
        var obj = {
            error: err.code,
            error_description: err.message
        };
        if (req.query.state) obj.state = req.query.state;
        redirectUri += '?' + query.stringify(obj);
        redirect(req, res, redirectUri);
    }
    else
        data(req, res, err.status, {error: err.code, error_description: err.message});
};

module.exports.data = function(req, res, obj, redirectUri, anchor) {
    if (redirectUri) {
        if (anchor)
            redirectUri += '#';
        else
            redirectUri += (redirectUri.indexOf('?') == -1 ? '?' : '&');
        if (req.query.state) obj.state = req.query.state;
        redirectUri += query.stringify(obj);
        redirect(req, res, redirectUri);
    }
    else
        data(req, res, 200, obj);
};
