/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
    jwtDecode = require('jwt-decode'),
    jwt = require('jwt-simple'),
    querystring = require('querystring'),
    serializer = require('serializer'),
    _ = require('underscore'),
    moment = require('moment');

function parse_authorization(authorization) {
  if (!authorization) {
    return null;
  }

  var parts = authorization.split(' ');

  if (parts.length !== 2 || parts[0] !== 'Basic') {
    return null;
  }

  var creds = new Buffer(parts[1], 'base64').toString(),
          i = creds.indexOf(':');

  if (i === -1) {
    return null;
  }

  var username = creds.slice(0, i);
      password = creds.slice(i + 1);

  return [username, password];
}

function OAuth2Provider(options) {
  if (arguments.length !== 1) {
    console.warn('OAuth2Provider(crypt_key, sign_key) constructor has been deprecated, yo.');

    options = {
      crypt_key: arguments[0],
      sign_key: arguments[1]
    };
  }

  options['authorize_uri'] = options['authorize_uri'] || '/oauth/authorize';
  options['access_token_uri'] = options['access_token_uri'] || '/oauth/access_token';

  this.options = options;
  this.serializer = serializer.createSecureSerializer(this.options.crypt_key, this.options.sign_key);
}

OAuth2Provider.prototype = new EventEmitter();

OAuth2Provider.prototype.generateAccessToken = function(user_id, client_id, extra_data, token_options) {
  token_options = token_options || {};

  var access_token, refresh_token;
  var client_secret = token_options.client_secret || self.options.crypt_key;
  if (token_options.client_secret) {
    // Unset client_secret as it's redundant in payload.
    delete token_options.client_secret;
  }

  // JWT access_token
  access_token = jwt.encode(_.extend(extra_data, token_options), client_secret);
  refresh_token = this.serializer.stringify([user_id, client_id, parseInt(moment().unix(), 10)]);

  var out = _.extend(token_options, {
    access_token: access_token,
    refresh_token: refresh_token
  });
  return out;
};

OAuth2Provider.prototype.login = function() {
  var self = this;

  return function(req, res, next) {
    var atok, tokenBody;
    atok = self._getTokenFromReq(req);

    if (!atok) {
      return next();
    }

    tokenBody = self._getTokenBody(atok);

    // Check whether token has expired.
    if (tokenBody.exp && tokenBody.exp < parseInt(moment().unix(), 10)) {
      return res.status(400).send('Access token invalid or expired');
    }

    self.emit('access_token', req, res, tokenBody, atok, next);
  };
};

OAuth2Provider.prototype.oauth = function() {
  var self = this;

  return function(req, res, next) {
    var uri = ~req.url.indexOf('?') ? req.url.substr(0, req.url.indexOf('?')) : req.url;

    if (req.method === 'GET' && self.options.authorize_uri === uri) {
      var client_id = req.query.client_id,
          redirect_uri = req.query.redirect_uri;

      if (!client_id || !redirect_uri) {
        res.writeHead(400);
        return res.end('client_id and redirect_uri required');
      }

      // authorization form will be POSTed to same URL, so we'll have all params
      var authorize_url = req.url;

      self.emit('enforce_login', req, res, authorize_url, function(user_id) {
        // store user_id in an HMAC-protected encrypted query param
        authorize_url += '&' + querystring.stringify({x_user_id: self.serializer.stringify(user_id)});

        // user is logged in, render approval page
        self.emit('authorize_form', req, res, client_id, authorize_url);
      });

    } else if (req.method === 'POST' && self.options.authorize_uri === uri) {
      var response_type = (req.query.response_type || req.body.response_type) || 'code',
          state = (req.query.state || req.body.state),
          x_user_id = (req.query.x_user_id || req.body.x_user_id);

      redirect_uri = (req.query.redirect_uri || req.body.redirect_uri);
      client_id = (req.query.client_id || req.body.client_id);

      var url = redirect_uri;

      switch(response_type) {
        case 'code': url += '?'; break;
        case 'token': url += '#'; break;
        default:
          res.writeHead(400);
          return res.end('invalid response_type requested');
      }

      if ('allow' in req.body) {
        if ('token' === response_type) {
          var user_id;

          try {
            user_id = self.serializer.parse(x_user_id);
          } catch(e) {
            console.error('allow/token error', e.stack);

            res.writeHead(500);
            return res.end(e.message);
          }

          self.emit('create_access_token', user_id, client_id, function(extra_data, token_options) {
            var atok = self.generateAccessToken(user_id, client_id, extra_data, token_options);

            if (self.listeners('save_access_token').length > 0)
              self.emit('save_access_token', user_id, client_id, atok);

            url += querystring.stringify(atok);

            res.writeHead(303, {Location: url});
            res.end();
          });
        } else {
          var code = serializer.randomString(128);

          self.emit('save_grant', req, client_id, code, function() {
            var extras = {
              code: code
            };

            // pass back anti-CSRF opaque value
            if (state) {
              extras['state'] = state;
            }

            url += querystring.stringify(extras);

            res.writeHead(303, {Location: url});
            res.end();
          });
        }
      } else {
        url += querystring.stringify({error: 'access_denied'});

        res.writeHead(303, {Location: url});
        res.end();
      }
    } else if (req.method === 'POST' && self.options.access_token_uri === uri) {
      var client_secret = req.body.client_secret,
          code = req.body.code;

      redirect_uri = req.body.redirect_uri;
      client_id = req.body.client_id;

      if (!client_id || !client_secret) {
        var authorization = parse_authorization(req.headers.authorization);

        if (!authorization) {
          res.writeHead(400);
          return res.end('client_id and client_secret required');
        }

        client_id = authorization[0];
        client_secret = authorization[1];
      }

      if ('password' === req.body.grant_type) {
        if (self.listeners('client_auth').length === 0) {
          res.writeHead(401);
          return res.end('client authentication not supported');
        }

        self.emit('client_auth', client_id, client_secret, req.body.username, req.body.password, function(err, user_id) {
          if (err) {
            res.writeHead(401);
            return res.end(err.message);
          }

          res.writeHead(200, {'Content-type': 'application/json'});

          self._createAccessToken(user_id, client_id, function(atok) {
            res.end(JSON.stringify(atok));
          });
        });
      } else {
        self.emit('lookup_grant', client_id, client_secret, code, function(err, user_id) {
          if (err) {
            res.writeHead(400);
            return res.end(err.message);
          }

          res.writeHead(200, {'Content-type': 'application/json'});

          self._createAccessToken(user_id, client_id, function(atok) {
            self.emit('remove_grant', user_id, client_id, code);

            res.end(JSON.stringify(atok));
          });
        });
      }

    } else {
      return next();
    }
  };
};

OAuth2Provider.prototype._createAccessToken = function(user_id, client_id, cb) {
  var self = this;

  this.emit('create_access_token', user_id, client_id, function(extra_data, token_options) {
    var atok = self.generateAccessToken(user_id, client_id, extra_data, token_options);

    if (self.listeners('save_access_token').length > 0)
      self.emit('save_access_token', user_id, client_id, atok);

    return cb(atok);
  });
};

// Prep Jwt body object.
OAuth2Provider.prototype.prepTokenBody = function(iss, sub, aud, exp) {
  var body = {
    iss: iss,
    sub: sub,
    aud: aud,
    iat: parseInt(moment().unix(), 10),
    exp: exp.key && exp.value ? parseInt(moment().add(exp.value, exp.key).unix(), 10) : null
  };

  return body;
};

// Helper function to get the bearer token from the authorization header.
OAuth2Provider.prototype._getTokenFromReq = function(req) {
  var pattern = /(Token|Bearer)\s/gi;

  if (!req.headers.authorization && !pattern.test(req.headers.authorization)) {
    return null;
  } else {
    return req.headers.authorization.replace(pattern, '');
  }
};

// Helper function for decoding JWT Token.
OAuth2Provider.prototype.verifyToken = function(token, secret) {
  try {
    if (jwt.decode(token, secret)) {
      return true;
    }
    return false;
  } catch(e) {
    console.log(e);
    return false;
  }
};

// Helper function for decoding JWT Token.
OAuth2Provider.prototype._getTokenBody = function(token) {
  return jwtDecode(token);
};

exports.OAuth2Provider = OAuth2Provider;
