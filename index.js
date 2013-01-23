/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
     querystring = require('querystring'),
      serializer = require('serializer');

function parse_authorization(authorization) {
  if(!authorization)
    return null;

  var parts = authorization.split(' ');

  if(parts.length != 2 || parts[0] != 'Basic')
    return null;

  var creds = new Buffer(parts[1], 'base64').toString(),
          i = creds.indexOf(':');

  if(i == -1)
    return null;

  var username = creds.slice(0, i);
      password = creds.slice(i + 1);

  return [username, password];
}

function OAuth2Provider(options) {
  if(arguments.length != 1) {
    console.warn('OAuth2Provider(crypt_key, sign_key) constructor has been deprecated, yo.');

    options = {
      crypt_key: arguments[0],
      sign_key: arguments[1],
    };
  }

  options['authorize_uri'] = options['authorize_uri'] || '/oauth/authorize';
  options['access_token_uri'] = options['access_token_uri'] || '/oauth/access_token';

  this.options = options;
  this.serializer = serializer.createSecureSerializer(this.options.crypt_key, this.options.sign_key);
}

OAuth2Provider.prototype = new EventEmitter();

OAuth2Provider.prototype.generateAccessToken = function(user_id, client_id, extra_data) {
  var out = {
    access_token: this.serializer.stringify([user_id, client_id, +new Date, extra_data]),
    refresh_token: null,
  };

  return out;
};

OAuth2Provider.prototype.login = function() {
  var self = this;

  return function(req, res, next) {
    var data, atok, user_id, client_id, grant_date, extra_data;

    if(req.query['access_token']) {
      atok = req.query['access_token'];
    } else if((req.headers['authorization'] || '').indexOf('Bearer ') == 0) {
      atok = req.headers['authorization'].replace('Bearer', '').trim();
    } else {
      return next();
    }

    try {
      data = self.serializer.parse(atok);
      user_id = data[0];
      client_id = data[1];
      grant_date = new Date(data[2]);
      extra_data = data[3];
    } catch(e) {
      res.writeHead(400);
      return res.end(e.message);
    }

    self.emit('access_token', req, {
      user_id: user_id,
      client_id: client_id,
      extra_data: extra_data,
      grant_date: grant_date
    }, next);
  };
};

OAuth2Provider.prototype.oauth = function() {
  var self = this;

  return function(req, res, next) {
    var uri = ~req.url.indexOf('?') ? req.url.substr(0, req.url.indexOf('?')) : req.url;

    if(req.method == 'GET' && self.options.authorize_uri == uri) {
      var    client_id = req.query.client_id,
          redirect_uri = req.query.redirect_uri;

      if(!client_id || !redirect_uri) {
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

    } else if(req.method == 'POST' && self.options.authorize_uri == uri) {
      var     client_id = (req.query.client_id || req.body.client_id),
           redirect_uri = (req.query.redirect_uri || req.body.redirect_uri),
          response_type = (req.query.response_type || req.body.response_type) || 'code',
                  state = (req.query.state || req.body.state),
              x_user_id = (req.query.x_user_id || req.body.x_user_id);

      var url = redirect_uri;

      switch(response_type) {
        case 'code': url += '?'; break;
        case 'token': url += '#'; break;
        default:
          res.writeHead(400);
          return res.end('invalid response_type requested');
      }

      if('allow' in req.body) {
        if('token' == response_type) {
          var user_id;

          try {
            user_id = self.serializer.parse(x_user_id);
          } catch(e) {
            console.error('allow/token error', e.stack);

            res.writeHead(500);
            return res.end(e.message);
          }

          self.emit('create_access_token', user_id, client_id, function(extra_data) {
            var atok = self.generateAccessToken(user_id, client_id, extra_data);

            if(self.listeners('save_access_token').length > 0)
              self.emit('save_access_token', user_id, client_id, atok);

            url += querystring.stringify(atok);

            res.writeHead(303, {Location: url});
            res.end();
          });
        } else {
          var code = serializer.randomString(128);

          self.emit('save_grant', req, client_id, code, function() {
            var extras = {
              code: code,
            };

            // pass back anti-CSRF opaque value
            if(state)
              extras['state'] = state;

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

    } else if(req.method == 'POST' && self.options.access_token_uri == uri) {
      var     client_id = req.body.client_id,
          client_secret = req.body.client_secret,
           redirect_uri = req.body.redirect_uri,
                   code = req.body.code;

      if(!client_id || !client_secret) {
        var authorization = parse_authorization(req.headers.authorization);

        if(!authorization) {
          res.writeHead(400);
          return res.end('client_id and client_secret required');
        }

        client_id = authorization[0];
        client_secret = authorization[1];
      }

      if('password' == req.body.grant_type) {
        if(self.listeners('client_auth').length == 0) {
          res.writeHead(401);
          return res.end('client authentication not supported');
        }

        self.emit('client_auth', client_id, client_secret, req.body.username, req.body.password, function(err, user_id) {
          if(err) {
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
          if(err) {
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

  this.emit('create_access_token', user_id, client_id, function(extra_data) {
    var atok = self.generateAccessToken(user_id, client_id, extra_data);

    if(self.listeners('save_access_token').length > 0)
      self.emit('save_access_token', user_id, client_id, atok);

    return cb(atok);
  });
};

exports.OAuth2Provider = OAuth2Provider;
