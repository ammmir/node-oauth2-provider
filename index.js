/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
     querystring = require('querystring'),
      serializer = require('serializer');

function OAuth2Provider(crypt_key, sign_key) {
  this.serializer = serializer.createSecureSerializer(crypt_key, sign_key);
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

    if(req.method == 'GET' && '/oauth/authorize' == uri) {
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

    } else if(req.method == 'POST' && '/oauth/authorize' == uri) {
      var     client_id = req.query.client_id,
           redirect_uri = req.query.redirect_uri,
          response_type = req.query.response_type || 'code',
                  state = req.query.state,
              x_user_id = req.query.x_user_id;

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

    } else if(req.method == 'POST' && '/oauth/access_token' == uri) {
      var     client_id = req.body.client_id,
          client_secret = req.body.client_secret,
           redirect_uri = req.body.redirect_uri,
                   code = req.body.code;

      self.emit('lookup_grant', client_id, client_secret, code, function(err, user_id) {
        if(err) {
          res.writeHead(400);
          return res.end(err.message);
        }

        res.writeHead(200, {'Content-type': 'application/json'});

        self.emit('create_access_token', user_id, client_id, function(extra_data) {
          var atok = self.generateAccessToken(user_id, client_id, extra_data);

          if(self.listeners('save_access_token').length > 0)
            self.emit('save_access_token', user_id, client_id, atok);

          res.end(JSON.stringify(self.generateAccessToken(user_id, client_id, extra_data)));
        });

        self.emit('remove_grant', user_id, client_id, code);
      });

    } else {
      return next();
    }
  };
};

exports.OAuth2Provider = OAuth2Provider;
