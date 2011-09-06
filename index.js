/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
     querystring = require('querystring'),
      serializer = require('serializer'),
         connect = require('connect');

function OAuth2Provider(crypt_key, sign_key) {
  this.serializer = serializer.createSecureSerializer(crypt_key, sign_key);
}

OAuth2Provider.prototype = new EventEmitter();

OAuth2Provider.prototype.login = function() {
  var self = this;

  return function(req, res, next) {
    var data, atok, user_id, client_id;

    if(req.query['access_token']) {
      atok = req.query['access_token'];
    } else if(req.headers['authorization']) {
      atok = req.headers['authorization'].replace('Bearer', '').trim();
    } else {
      return next();
    }

    try {
      data = self.serializer.parse(atok);
      user_id = data[0];
      client_id = data[1];
    } catch(e) {
      res.writeHead(400);
      return res.end(e.message);
    }

    self.emit('access_token', req, user_id, client_id, next);
  };
};

OAuth2Provider.prototype.oauth = function() {
  var self = this;

  return connect.router(function(app) {
    app.get('/oauth/authorize', function(req, res, next) {
      var    client_id = req.query.client_id,
          redirect_uri = req.query.redirect_uri,
                 scope = req.query.scope, // optional
                  type = req.query.type; // 'web_server'

      if(!client_id || !redirect_uri) {
        res.writeHead(400);
        return res.end('client_id and redirect_uri required');
      }

      var authorize_url = req.url;

      self.emit('enforce_login', req, res, authorize_url, function() {
        // user is logged in, render approval page
        self.emit('authorize_form', req, res, authorize_url);
      });
    });

    app.post('/oauth/authorize', function(req, res, next) {
      var    client_id = req.query.client_id,
          redirect_uri = req.query.redirect_uri;

      var url = redirect_uri + '?';

      if('allow' in req.body) {
        var code = serializer.randomString(128);
        self.emit('save_grant', req, client_id, code);

        url += querystring.stringify({code: code});
      } else if('deny' in req.body) {
        url += querystring.stringify({error: 'access_denied'});
      }

      // redirect back to redirect_uri?code=...
      res.writeHead(303, {Location: url});
      return res.end();
    });

    app.post('/oauth/access_token', function(req, res, next) {
      var     client_id = req.body.client_id,
          client_secret = req.body.client_secret,
           redirect_uri = req.body.redirect_uri,
                   code = req.body.code;

      self.emit('lookup_grant', client_id, client_secret, code, function(err, user_id) {
        if(err) {
          res.writeHead(400);
          return res.end(err.message);
        }

        var out = {
          access_token: self.serializer.stringify([user_id, client_id]),
          refresh_token: null,
        };

        res.writeHead(200, {'Content-type': 'application/json'});
        res.end(JSON.stringify(out));

        self.emit('remove_grant', user_id, client_id, code);
      });
    });
  });
};

exports.OAuth2Provider = OAuth2Provider;
