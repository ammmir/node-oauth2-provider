/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
     querystring = require('querystring'),
      serializer = require('serializer'),
      redis = require('redis').createClient(),
      extend = require('extend'),
      url = require('url');

      
var defaults = {
  authorize_uri: '/authorize',
  access_token_uri: '/access_token',
  login_uri: '/login',
  create_user_uri: '/create_user',
  register_app_uri: '/register_app',
  consent_uri: '/consent',
  scopes: {
    openid: 'Informs the Authorization Server that the Client is making an OpenID Connect request.', 
    profile:'Access to the End-User\'s default profile Claims.', 
    email: 'Access to the email and email_verified Claims.', 
    address: 'Access to the address Claim.', 
    phone: 'Access to the phone_number and phone_number_verified Claims.', 
    offline_access: 'Grants access to the End-User\'s UserInfo Endpoint even when the End-User is not present (not logged in).'
  },
  redis_prefix: 'openid:connect:'
};

_extend = function(dst,src) {

  var srcs = [];
  if ( typeof(src) == 'object' ) {
    srcs.push(src);
  } else if ( typeof(src) == 'array' ) {
    for (var i = src.length - 1; i >= 0; i--) {
      srcs.push(this._extend({},src[i]))
    };
  } else {
    throw new Error("Invalid argument")
  }

  for (var i = srcs.length - 1; i >= 0; i--) {
    for (var key in srcs[i]) {
      dst[key] = srcs[i][key];
    }
  };

  return dst;
}
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

function OpenIDConnect(options) {
  this.options = extend(true, {}, options, defaults);
  this.serializer = serializer.createSecureSerializer(this.options.crypt_key, this.options.sign_key);
}

OpenIDConnect.prototype = new EventEmitter();

OpenIDConnect.prototype.generateAccessToken = function(user_id, client_id, extra_data, token_options) {
  var out = extend(token_options || {}, {
    access_token: this.serializer.stringify([user_id, client_id, +new Date, extra_data]),
    refresh_token: null,
  });
  return out;
};

OpenIDConnect.prototype.errorHandle = function(res, uri, error, desc) {
  if(uri) {
    var redirect = url.parse(uri,true);
    redirect.query.error = error; //'invalid_request';
    redirect.query.error_description = desc; //'Parameter '+x+' is mandatory.';
    res.redirect(url.fromat(redirect));
  } else {
    res.send(400, error+': '+desc);
  }
};

OpenIDConnect.prototype.auth = function() {
  var self = this;
  return [
    function(req, res, next) {
      /*
      * Authorization Server authenticates the End-User.
      */
      var spec = {
	response_type: true, 
	client_id: true, 
	scope: true, 
	redirect_uri: true, 
	state: false, 
	nonce: false, 
	display: false, 
	prompt: false, 
	max_age: false, 
	ui_locales: false, 
	claims_locales: false, 
	id_token_hint: false, 
	login_hint: false, 
	acr_values: false
      };
      var params = {};
      var r = req.query.redirect_uri || req.body.redirect_uri;
      for(var i in spec) {
	var x = req.query[i] || req.body[i] || false;
	if(!x && spec[i] !== false) {
	  self.errorHandle(res, r, 'invalid_request', 'Parameter '+x+' is mandatory.');
	  return;
	}
	if(x) {
	  params[i] = x;
	}
      }
      switch(params.response_type) {
	case 'code':
	  if(req.session.user) {
	    next();
	  } else {
	    var client = redis.get(self.options.redis_prefix+params.client_id+':client_app');
	    if(!client || client == '') {
	      self.errorHandle(res, r, 'invalid_request', 'Client '+params.client_id+' doesn\'t exist.');
	      return;
	    }
	    var q = req.path+'?'+querystring.stringify(params);
	    res.redirect(self.options.login_uri+'?'+querystring.stringify({return_url: q}));
	  }
	  break;
	default:
	  self.errorHandle(res, r, 'unsupported_response_type', 'Response type '+options.response_type+' not supported.');
      }
    },
    function(req, res, next) {
      /*
      * Authorization Server obtains the End-User Consent/Authorization.
      */
      var spec = {
	response_type: true, 
	client_id: true, 
	scope: true, 
	redirect_uri: true, 
	state: false, 
	nonce: false, 
	display: false, 
	prompt: false, 
	max_age: false, 
	ui_locales: false, 
	claims_locales: false, 
	id_token_hint: false, 
	login_hint: false, 
	acr_values: false
      };
      var params = {};
      var r = req.query.redirect_uri || req.body.redirect_uri;
      for(var i in spec) {
	var x = req.query[i] || req.body[i] || false;
	if(!x && spec[i] !== false) {
	  self.errorHandle(res, r, 'invalid_request', 'Parameter '+x+' is mandatory.');
	  return;
	}
	if(x) {
	  params[i] = x;
	}
      }
      if(!/(^|.*\W)openid(\W.*|$)/.test(params.scope)) {
	self.errorHandle(res, r, 'invalid_request', 'Scope openid is mandatory.');
	return;
      }
      var reqsco = params.scope.split(' ');
      req.session.scopes = {};
      var consent_redirect = false;
      for(var i in reqsco) {
	if(!self.options.scopes[i]) {
	  self.errorHandle(res, r, 'invalid_scope', 'Scope '+i+' not supported'.);
	  return;
	}
	req.session.scopes[i] = redis.sismember(self.options.redis_prefix+req.session.user+':scopes', i);
	if(!scopes[i]) {
	  consent_redirect = true;
	}
      }
      if(!consent_redirect) {
	next();
      } else {
	var q = req.path+'?'+querystring.stringify(params);
	res.redirect(self.options.consent_uri+'?'+querystring.stringify({return_url: q}));
      }
    },
    function(req, res, next) {
      /*
      * Authorization Server sends the End-User back to the Client with code.
      */
      var spec = {
	response_type: true, 
	client_id: true, 
	scope: true, 
	redirect_uri: true, 
	state: false, 
	nonce: false, 
	display: false, 
	prompt: false, 
	max_age: false, 
	ui_locales: false, 
	claims_locales: false, 
	id_token_hint: false, 
	login_hint: false, 
	acr_values: false
      };
      var params = {};
      var r = req.query.redirect_uri || req.body.redirect_uri;
      for(var i in spec) {
	var x = req.query[i] || req.body[i] || false;
	if(!x && spec[i] !== false) {
	  self.errorHandle(res, r, 'invalid_request', 'Parameter '+x+' is mandatory.');
	  return;
	}
	if(x) {
	  params[i] = x;
	}
      }
      switch(params.response_type) {
	case 'code':
	  var token = self.serializer.stringify([req.session.user, params.client_id, Math.random()]);
	  redis.set(self.options.redis_prefix+req.session.user+':'+token, 'created');
	  setTimeout(function() {
	    if(redis.get(self.options.redis_prefix+req.session.user+':'+token) == 'created') {
	      redis.del(self.options.redis_prefix+req.session.user+':'+token);
	    }
	  }, 1000*60*10); //10 minutes
	  var uri = url.parse(params.redirect_uri, true);
	  uri.query.code = token;
	  if(params.state) {
	    uri.query.state = params.state;
	  }
	  res.redirect(url.format(uri));
	  break;
	default:
	  self.errorHandle(res, r, 'unsupported_response_type', 'Response type '+options.response_type+' not supported.');
      }
    }
  ];
};

OpenIDConnect.prototype.setConcent = function() {
  var self = this;
  return function(req, res, next) {
    var accept = req.query.accept || req.body.accept || false;
    var return_url = req.query.accept || req.body.accept || false;
    if(accept) {
      for(var i in req.session.scopes) {
	redis.sadd(self.options.redis_prefix+req.session.user+':scopes', i)
      }
      res.redirect(return_url);
    } else {
      var returl = url.parse(return_url, true);
      var redirect_uri = returl.query.redirect_uri;
      self.errorHandle(req, redirect_uri, 'access_denied', 'Resource Owner denied Access.');
    }
  };
};

/*
 * Client sends the code to the Token Endpoint to receive an Access Token and ID Token in the response.
*/
OpenIDConnect.prototype.token = function() {
};


/*
OpenIDConnect.prototype.login = function() {
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

          self.emit('create_access_token', user_id, client_id, function(extra_data,token_options) {
            var atok = self.generateAccessToken(user_id, client_id, extra_data, token_options);

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

  this.emit('create_access_token', user_id, client_id, function(extra_data, token_options) {
    var atok = self.generateAccessToken(user_id, client_id, extra_data, token_options);

    if(self.listeners('save_access_token').length > 0)
      self.emit('save_access_token', user_id, client_id, atok);

    return cb(atok);
  });
};
*/
exports.OpenIDConnect = OpenIDConnect;
