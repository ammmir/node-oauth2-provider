/**
 * index.js
 * OpenIDConnect provider
 * Based on OAuth 2.0 provider by Amir Malik 
 *
 * @author Agustín Moyano
 */

var EventEmitter = require('events').EventEmitter,
querystring = require('querystring'),
//serializer = require('serializer'),
//hashlib = require('hashlib2'),
crypto = require('crypto'),
extend = require('extend'),
url = require('url'),
Q = require('q'),
jwt = require('jwt-simple'),
util = require("util");

var modelObj = {
		global: {
			authClientCredential: {type: 'set', refs: true}
		},
		user: {
			_obj: {
				type: 'hash',
				reverse: ['email'],
				props: {
					name: {mandatory: true},
					given_name: {html: 'input', mandatory: true},
					middle_name: {html: 'input', mandatory: false},
					family_name: {html: 'input', mandatory: true},
					profile: {mandatory: false},
					email: {html: 'input', mandatory: true},
					password: {html: 'password'},
					picture: {html: 'file'},
					birthdate: {html: 'date'},
					gender: {html: 'radio', ops: ['male', 'female']},
					phone_number: {html: 'input'}
				}
			},
			clients: {type: 'set', refs: true}
		},
		client: {
			_obj: {
				type: 'hash',
				reverse: ['id'],
				props: {
					id: {html: 'fixed', mandatory: true},
					secret: {html: 'fixed', mandatory: true},
					name: {html: 'input', mandatory: true},
					image: {mandatory: false},
					user: {mandatory: true}
				}
			},
			redirect_uris: {type: 'set'}
		},
		consent: {
			_obj: {
				type: 'hash',
				reverse: ['user', 'client'],
				props: {
					user: {mandatory: true},
					client: {mandatory: true}
				},
			},
			scopes: {type: 'set'}
		},
		auth: {
			_obj: {
				type: 'hash',
				reverse: ['code'],
				props: {
					clientId: {mandatory: true},
					scope: {mandatory: true},
					user: {mandatory: true},
					code: {mandatory: true},
					redirectUri: {mandatory: true},
					responseType: {mandatory: true},
					status: {mandatory: true}
				}
			},
			accessTokens: {type: 'set'},
			refreshTokens: {type: 'set'}
		},
		access: {
			_obj: {
				type: 'hash',
				reverse: ['token'],
				props: {
					token: {mandatory: true},
					type: {mandatory: true},
					idToken: {mandatory: false},
					expiresIn: {mandatory: false},
					scope: {mandatory: true},
					clientId: {mandatory: true},
					user: {mandatory: true},
					auth: {refs: true}
				}
			}
		},
		refresh: {
			_obj: {
				type: 'hash',
				reverse: ['token'],
				props: {
					token: {mandatory: true},
					scope: {mandatory: true},
					auth: {refs: true},
					status: {mandatory: true}
				}
			}
		}
};

var defaults = {
		login_url: '/login',
		consent_url: '/consent',
		scopes: {
			openid: 'Informs the Authorization Server that the Client is making an OpenID Connect request.', 
			profile:'Access to the End-User\'s default profile Claims.', 
			email: 'Access to the email and email_verified Claims.', 
			address: 'Access to the address Claim.', 
			phone: 'Access to the phone_number and phone_number_verified Claims.', 
			offline_access: 'Grants access to the End-User\'s UserInfo Endpoint even when the End-User is not present (not logged in).'
		},
		redis_prefix: 'oidc:'
};

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
	var rm = require('redis-modelize');
	this.model = rm.init(modelObj, {prefix: this.options.redis_prefix});
	this.redisClient = rm.client;
}

OpenIDConnect.prototype = new EventEmitter();

OpenIDConnect.prototype.getClientParams = function() {
	return this.model.client.getParams();
};

OpenIDConnect.prototype.client = function(params, callback) {
	return new this.model.client(params, callback);
};

OpenIDConnect.prototype.searchClient = function(parts, callback) {
	return new this.model.client.reverse(parts, callback);
};

OpenIDConnect.prototype.getUserParams = function() {
	return this.model.user.getParams();
};

OpenIDConnect.prototype.user = function(params, callback) {
	return new this.model.user(params, callback);
};

OpenIDConnect.prototype.searchUser = function(parts, callback) {
	return new this.model.user.reverse(parts, callback);
};

OpenIDConnect.prototype.errorHandle = function(res, uri, error, desc) {
	if(uri) {
		var redirect = url.parse(uri,true);
		redirect.query.error = error; //'invalid_request';
		redirect.query.error_description = desc; //'Parameter '+x+' is mandatory.';
		res.redirect(400, url.format(redirect));
	} else {
		res.send(400, error+': '+desc);
	}
};


OpenIDConnect.prototype.parseParams = function(req, res, spec) {
	var params = {};
	var r = req.query.redirect_uri || req.body.redirect_uri;
	for(var i in spec) {
		var x = req.query[i] || req.body[i] || false;
		if(x) {
			params[i] = x;
		}
	}

	for(var i in spec) {
		var x = params[i];
		if(!x) {
			var error = false;
			if(typeof spec[i] == 'boolean') {
				error = spec[i];
			} else if (typeof spec[i] == 'object') {
				for(var j in spec[i]) {
					if(!util.isArray(spec[i][j])) {
						spec[i][j] = [spec[i][j]];
					}
					spec[i][j].forEach(function(e) {
						if(!error) {
							if(util.isRegExp(e)) {
								error = e.test(params[j]);
							} else {
								error = e == params[j];
							}
						}
					});
				}
			}

			if(error) {
				throw {type: 'error', uri: r, error: 'invalid_request', msg: 'Parameter '+x+' is mandatory.'};
				//self.errorHandle(res, r, 'invalid_request', 'Parameter '+x+' is mandatory.');
				//return;
			}
		}
	}
	return params;
};

/**
 * auth
 * 
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 * 
 * app.get('/authorization', oidc.auth());
 * 
 * This is the authorization endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.1
 * 
 */
OpenIDConnect.prototype.auth = function() {
	var self = this;
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
	var redis = this.redisClient;
	return [
	        function(req, res, next) {
	        	Q(self).post('parseParams', [req, res, spec])
	        	.then(function(params) {
	        		//Step 1: Check if user is logged in

	        		if(req.session.user) {
	        			//next();
	        			return params;
	        		} else {
	        			var q = req.path+'?'+querystring.stringify(params);
	        			throw {type: 'redirect', uri: self.options.login_url+'?'+querystring.stringify({return_url: q})};  
	        		}
	        	}).then(function(params) {
	        		//Step 2: Check if response_type is supported and client_id is valid.

	        		var deferred = Q.defer();
	        		switch(params.response_type) {
	        		case 'none':
	        		case 'code':
	        		case 'token':
	        		case 'id_token':
	        			break;
	        		default:
	        			var error = false;
	        		var sp = params.response_type.split(' ');
	        		sp.forEach(function(response_type) {
	        			if(['code', 'token', 'id_token'].indexOf(response_type) == -1) {
	        				throw {type: 'error', uri: params.redirect_uri, error: 'unsupported_response_type', msg: 'Response type '+response_type+' not supported.'};
	        			}
	        		});
	        		}	    
	        		self.searchClient(params.client_id, function(err, reply){
	        			if(err || !reply || reply == '') {
	        				deferred.reject({type: 'error', uri: params.redirect_uri, error: 'invalid_client', msg: 'Client '+params.client_id+' doesn\'t exist.'});
	        			} else {
	        				req.session.redis_client_id = reply;
	        				this.get(function(err, obj) {
	        					req.session.redis_client_secret = obj.secret;
	        					deferred.resolve(params);
	        				});
	        			}
	        		});
	        		return deferred.promise;
	        	}).then(function(params){
	        		//Step 3: Check if scopes are valid, and if consent was given.

	        		var deferred = Q.defer();
	        		var reqsco = params.scope.split(' ');
	        		req.session.scopes = {};
	        		var promises = [];
	        		self.model.consent.reverse([req.session.user, params.client_id], function(err, grant_id) {
	        			reqsco.forEach(function(scope) {
	        				var innerDef = Q.defer();
	        				if(!self.options.scopes[scope]) {
	        					throw {type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Scope '+scope+' not supported.'};
	        				}
	        				if(!grant_id) {
	        					req.session.scopes[scope] = {ismember: false, explain: self.options.scopes[scope]};
	        					innerDef.resolve(true);
	        				} else {
	        					this.inScopes(scope, function(err, response) {
	        						req.session.scopes[scope] = {ismember: response, explain: self.options.scopes[scope]};
	        						if(!response) {
	        							innerDef.resolve(true);
	        						} else {
	        							innerDef.resolve(false);
	        						}
	        					});
	        				}
	        				promises.push(innerDef.promise)
	        			});
	        		});
	        		Q.allSettled(promises).then(function(results){
	        			var redirect = false;
	        			for(var i = 0; i<results.length; i++) {
	        				if(results[i].value) {
	        					redirect = true;
	        					break;
	        				}
	        			}
	        			if(redirect) {
	        				req.session.client_id = params.client_id;
	        				var q = req.path+'?'+querystring.stringify(params);
	        				deferred.reject({type: 'redirect', uri: self.options.consent_url+'?'+querystring.stringify({return_url: q})});
	        			} else {
	        				deferred.resolve(params);
	        			}
	        		});
	        		return deferred.promise;
	        	}).then(function(params){
	        		//Step 5: create responses
	        		if(params.response_type == 'none') {
	        			return {params: params, resp: {}};
	        		} else {	
	        			var deferred = Q.defer();
	        			var promises = [];

	        			var rts = params.response_type.split(' ');

	        			rts.forEach(function(rt) {
	        				var def = Q.defer();
	        				promises.push(def.promise);
	        				switch(rt) {
	        				case 'code':
	        					var createToken = function() {
	        					var token = crypto.createHash('md5').update(Math.random()).digest();
	        					redis.sismember(self.options.redis_prefix+'tokens', token, function(err, response) {
	        						if(!response) {
	        							redis.sadd(self.options.redis_prefix+'tokens', token);
	        							setToken(token);
	        						} else {
	        							createToken();
	        						}
	        					});
	        				};
	        				var setToken = function(token) {
	        					var p = new self.model.auth({
	        						clientId: params.client_id,
	        						scope: params.scope,
	        						user: req.session.user,
	        						code: token,
	        						redirectUri: params.redirect_uri,
	        						responseType: params.response_type,
	        						status: 'created'
	        					});
	        					setTimeout(function() {
	        						p.getStatus(function(err, response) { 
	        							if(response == 'created') {
	        								p.del();
	        								redis.srem(self.options.redis_prefix+'tokens', token);
	        							}
	        						});
	        					}, 1000*60*10); //10 minutes
	        					def.resolve({code: token});
	        				};
	        				createToken();
	        				break;
	        				case 'id_token':
	        					var d = Math.round(new Date().getTime()/1000);
	        					var id_token = {
	        							iss: req.protocol+'://'+req.headers.host,
	        							sub: req.session.user,
	        							aud: params.client_id,
	        							exp: d+3600,
	        							iat: d
	        					};
	        					def.resolve({id_token: jwt.encode(id_token, req.session.redis_client_secret)});
	        					break;
	        				case 'token':
	        					var createToken = function() {
	        					var token = crypto.createHash('md5').update(Math.random()).digest();
	        					redis.sismember(self.options.redis_prefix+'tokens', token, function(err, response) {
	        						if(!response) {
	        							redis.sadd(self.options.redis_prefix+'tokens', token);
	        							setToken(token);
	        						} else {
	        							createToken();
	        						}
	        					});
	        				};
	        				var setToken = function(token) {
	        					var obj = {
	        							token: token,
	        							type: 'Bearer',
	        							expiresIn: 3600,
	        							user: req.session.user,
	        							clientId: params.client_id,
	        							scope: params.scope
	        					};
	        					new self.model.access(obj, function(err, id) {
	        						if(!err && id) {
	        							var a = this;

	        							setTimeout(function() {
	        								a.del();
	        								redis.srem(self.options.redis_prefix+'tokens', token);
	        							}, 1000*3600); //1 hour		

	        							def.resolve({
	        								access_token: obj.token,
	        								token_type: obj.type,
	        								expires_in: obj.expiresIn
	        							});
	        						}
	        					});
	        				};
	        				createToken();
	        				break;
	        				}
	        			});

	        			Q.allSettled(promises).then(function(results) {
	        				var resp = {};
	        				for(var i in results) {
	        					resp = extend(resp, results[i].value||{});
	        				}
	        				deferred.resolve({params: params, type: params.response_type != 'code'?'f':'q', resp: resp});
	        			});

	        			return deferred.promise;
	        		}
	        	})
	        	.then(function(obj) {
	        		var params = obj.params;
	        		var resp = obj.resp;
	        		var uri = url.parse(params.redirect_uri, true);
	        		if(params.state) {
	        			resp.state = params.state;
	        		}
	        		if(params.redirect_uri) {
	        			if(obj.type == 'f') {
	        				uri.hash = querystring.stringify(resp);
	        			} else {
	        				uri.query = resp;
	        			}
	        			res.redirect(url.format(uri));
	        		}
	        	})
	        	.fail(function(error) {
	        		if(error.type == 'error') {
	        			self.errorHandle(res, error.uri, error.error, error.msg);
	        		} else {
	        			res.redirect(error.uri);
	        		}
	        	}); 
	        }
	        ];
};

/**
 * consent
 * 
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 * 
 * app.post('/consent', oidc.consent());
 * 
 * This method saves the consent of the resource owner to a client request, or returns an access_denied error.
 * 
 */
OpenIDConnect.prototype.consent = function() {
	var self = this;
	return function(req, res, next) {
		var accept = req.query.accept || req.body.accept || false;
		var return_url = req.query.return_url || req.body.return_url || false;
		//var client_id = req.query.client_id || req.body.client_id || false;
		if(accept) {
			new self.model.consent({user: req.session.user, client: req.session.client_id}, function(err, id) {
				for(var i in req.session.scopes) {
					this.setScopes(i);
				}
				res.redirect(return_url);
			});
		} else {
			var returl = url.parse(return_url, true);
			var redirect_uri = returl.query.redirect_uri;
			self.errorHandle(res, redirect_uri, 'access_denied', 'Resource Owner denied Access.');
		}
	};
};


/**
 * token
 * 
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 * 
 * app.get('/token', oidc.token());
 * 
 * This is the token endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.2
 * 
 */
OpenIDConnect.prototype.token = function() {
	var self = this;
	var spec = {
			grant_type: true, 
			code: false, 
			redirect_uri: false,
			refresh_token: false,
			scope: false
	};
	var redis = this.redisClient;

	return function(req, res, next) {
		var params = self.parseParams(req, res, spec);

		params.client_id = req.body.client_id;
		params.client_secret = req.body.client_secret;

		if(!params.client_id || !params.client_secret) {
			var authorization = parse_authorization(req.headers.authorization);
			params.client_id = authorization[0];
			params.client_secret = authorization[1];
		}
		if(!params.client_id || !params.client_secret) {
			self.errorHandle(res, params.redirect_uri, 'invalid_client', 'No client credentials found.');
		} else {

			Q.fcall(function() {
				//Step 1: Check if user is logged in

				if(req.session.user) {
					//next();
					return true;
				} else {
					var q = req.path+'?'+querystring.stringify(params);
					throw {type: 'redirect', uri: self.options.login_url+'?'+querystring.stringify({return_url: q})};  
				}
			})
			.then(function() {
				//Step 2: check if client and secret are valid
				var deferred = Q.defer();
				self.searchClient(params.client_id, function(err, redis_client_id){
					if(err || !redis_client_id || redis_client_id == '') {
						deferred.reject({type: 'error', error: 'invalid_client', msg: 'Client doesn\'t exist or invalid secret.'});
					} else {
						this.getSecret(function(err, secret) {
							if(!err && secret == params.client_secret) {
								deferred.resolve(this);
							} else {
								deferred.reject({type: 'error', error: 'invalid_client', msg: 'Client doesn\'t exist or invalid secret.'});
							}
						});
					}
				});
				return deferred.promise;
			})
			.then(function(client) {

				var deferred = Q.defer();

				switch(params.grant_type) {
				//Client is trying to exchange an authorization code for an access token
				case "authorization_code":
					//Step 3: check if code is valid and not used previously
					self.model.auth.reverse(params.code, function(err, auth) {
						if(!err && auth) {
							var a = this;
							this.get(function(err, obj) {
								if(obj.status != 'created') {
									a.getAccessTokens(function(err, tokens){
										tokens.forEach(function(token) {
											new self.model.access(token).del();
										});
										a.getRefreshTokens(function(err, tokens) {
											tokens.forEach(function(token) {
												new self.model.refresh(token).del();
											});
											a.del();
										});
									});
									deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Authorization code already used.'});
								} else {
									obj.auth = a;
									deferred.resolve(obj);
								}
							});
						} else {
							deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Authorization code is invalid.'});
						}
					});

					//Extra checks, required if grant_type is 'authorization_code'
					return deferred.promise.then(function(obj){
						//Step 4: check if grant_type is valid

						if(obj.responseType != 'code') {
							throw {type: 'error', error: 'unauthorized_client', msg: 'Client cannot use this grant type.'};
						}

						//Step 5: check if redirect_uri is valid
						if((obj.redirectUri || params.redirect_uri) && obj.redirectUri != params.redirect_uri) {
							throw {type: 'error', error: 'invalid_grant', msg: 'Redirection URI does not match.'};
						}

						return obj;
					});

					break;

					//Client is trying to exchange a refresh token for an access token
				case "refresh_token":

					//Step 3: check if refresh token is valid and not used previously
					self.model.refresh.reverse(params.refresh_token, function(err, refresh) {
						if(!err && refresh) {
							this.getStatus(function(err, status) {
								var r = this;
								this.getRefAuth(function(err, auth) {
									if(status != 'created') {
										auth.getAccessTokens(function(err, tokens){
											tokens.forEach(function(token) {
												new self.model.access(token).del();
											});
											auth.getRefreshTokens(function(err, tokens) {
												tokens.forEach(function(token) {
													new self.model.refresh(token).del();
												});
												auth.del();
											});
										});
										deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token already used.'});
									} else {
										r.setStatus('used');
										auth.get(function(err, obj) {
											obj.auth = auth;
											deferred.resolve(obj);
										});
									}
								});
							});
						} else {
							deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token is not valid.'});
						}
					});
					return deferred.promise.then(function(obj){
						if(params.scope) {
							var scopes = params.scope.split(' ');
							var objScopes = obj.scope.split(' ');
							scopes.forEach(function(scope) {
								if(objScopes.indexOf(scope) == -1) {
									throw {type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Scope '+scope+' was not granted for this token.'};
								}
							});
							obj.scope = params.scope;
						}
						return obj;
					});
					break;
				case 'client_credentials':
					self.model.global.getRefAuthClientCredential(function(err, response) {
						if(!util.isArray(response)) {
							response = [response];
						}
						var inList = false;
						for(var i = 0; i<response.lenght; i++) {
							if(client.id == response[i].id) {
								inList = true;
								break;
							}
						}
						if(!inList) {
							deferred.reject({type: 'error', error: 'unauthorized_client', msg: 'Client cannot use this grant type.'});
						} else {
							deferred.resolve({scope: params.scope, auth: false});
						}
					});
					return deferred.promise;
					break;
				}

			})
			.then(function(obj) {
				//Check if code was issued for client
				if(params.grant_type != 'client_credentials' && obj.clientId != params.client_id) {
					throw {type: 'error', error: 'invalid_grant', msg: 'The code was not issued for this client.'};
				}

				return obj;

			})
			.then(function(obj){
				//Create access token
				var scopes = obj.scope;
				var auth = obj.auth;

				var createToken = function(cb) {
					var token = crypto.createHash('md5').update(Math.random()).digest();
					redis.sismember(self.options.redis_prefix+'tokens', token, function(err, response) {
						if(!response) {
							redis.sadd(self.options.redis_prefix+'tokens', token);
							cb(token);
						} else {
							createToken(cb);
						}
					});
				};
				var setToken = function(access, refresh) {
					var obj = {
							token: refresh,
							scope: scopes,
							status: 'created'
					};
					new self.model.refresh(obj, function(err, id) {
						var r = this;
						if(auth) {
							this.setRefAuth(auth);
							auth.setRefreshTokens(id);
						}
						setTimeout(function() {
							r.del();
							redis.srem(self.options.redis_prefix+'tokens', refresh);
							if(auth) {
								auth.remRefreshTokens(id, function() {
									auth.getAccessTokens(function(err, atoks){
										if(atoks) return;
										auth.getRefreshTokens(function(err, rtoks){
											if(rtoks) return;
											auth.del();
										});
									});
								});
							}
						}, 1000*3600*5); //5 hours

						var d = Math.round(new Date().getTime()/1000);
						var id_token = {
								iss: req.protocol+'://'+req.headers.host,
								sub: req.session.user,
								aud: params.client_id,
								exp: d+3600,
								iat: d
						};
						var obj = {
								token: access,
								type: 'Bearer',
								expiresIn: 3600,
								user: req.session.user,
								clientId: params.client_id,
								idToken: jwt.encode(id_token, params.client_secret),
								scope: scopes
						};
						new self.model.access(obj, function(err, id) {
							if(!err && id) {
								var a = this;
								if(auth) {
									this.setRefAuth(auth);
									auth.setAccessTokens(id);
									auth.setStatus('used');
								}

								setTimeout(function() {
									a.del();
									redis.srem(self.options.redis_prefix+'tokens', access);
									if(auth) {
										auth.remAccessTokens(id, function() {
											auth.getAccessTokens(function(err, atoks){
												if(atoks) return;
												auth.getRefreshTokens(function(err, rtoks){
													if(rtoks) return;
													auth.del();
												});
											});
										});
									}
								}, 1000*3600); //1 hour		

								res.json({
									access_token: access,
									token_type: obj.type,
									expires_in: obj.expiresIn,
									refresh_token: refresh,
									id_token: obj.idToken
								});
							}
						});
					}); 
				};
				createToken(function(access) {
					createToken(function(refresh){
						setToken(access, refresh);
					});
				});
			})
			.fail(function(error) {
				if(error.type == 'error') {
					self.errorHandle(res, params.redirect_uri, error.error, error.msg);
				} else {
					res.redirect(error.uri);
				}
			}); 
		}
	};
};


/** 
 * check
 * 
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 * 
 * app.get('/api/user', oidc.check('openid', /profile|email/), function(req, res, next) { ... });
 * 
 * If no arguments are given, checks if user is logged in.
 * 
 * The other arguments may be of type string or regexp.
 * 
 * This function is used to check if user logged in, if an access_token is present, and if certain scopes where granted to it.
 */
OpenIDConnect.prototype.check = function() {
	var scopes = Array.prototype.slice.call(arguments, 0);
	if(!util.isArray(scopes)) {
		scopes = [scopes];
	}
	var self = this;
	spec = {
			access_token: false
	};

	return function(req, res, next) {
		if(req.session.user) {
			var params = self.parseParams(req, res, spec);
			if(!scopes.length) {
				next();
			} else {
				if(!params.access_token) {
					params.access_token = (req.headers['authorization'] || '').indexOf('Bearer ') == 0?req.headers['authorization'].replace('Bearer', '').trim():false;
				}
				if(params.access_token) {
					self.model.access.reverse(params.access_token, function(err, id) {
						if(!err && id) {
							this.get(function(err, obj) {
								if(obj.user == req.session.user) {
									var errors = [];
									scopes.forEach(function(scope) {
										if(typeof scope == 'string') {
											if(obj.scope.indexOf(scope) == -1) {
												errors.push(scope);
											}
										} else if(util.isRegExp(scope) && !scope.test(obj.scope)){
											errors.push('('+scope.toString().replace(/\//g,'')+')');
										}
									});
									if(errors.length > 1) {
										var last = errors.pop();
										self.errorHandle(res, null, 'invalid_scope', 'Required scopes '+errors.join(', ')+' and '+last+' where not granted.');
									} else if(errors.length > 0) {
										self.errorHandle(res, null, 'invalid_scope', 'Required scope '+errors.pop()+' not granted.');
									} else {
										req.session.check = req.session.check||{};
										req.session.check.scopes = obj.scope.split(' ');
										next();
									}
								} else {
									//Delete access token, and every thing related to it.
									this.getRefAuth(function(err, auth) {
										if(!err && auth) {
											auth.getAccessTokens(function(err, tokens){
												tokens.forEach(function(token) {
													new self.model.access(token).del();
												});
												auth.getRefreshTokens(function(err, tokens) {
													tokens.forEach(function(token) {
														new self.model.refresh(token).del();
													});
													auth.del();
												});
											});
										}
									});
									self.errorHandle(res, null, 'invalid_grant', 'Access token issued for an other user.');
								}
							});
						} else {
							self.errorHandle(res, null, 'unauthorized_client', 'Access token is not valid.');
						}
					});
				} else {
					self.errorHandle(res, null, 'unauthorized_client', 'No access token found.');
				}
			}
		} else {
			 res.json(403, {error: 'unauthorized', error_description: 'You must login to use this resource.'});  
		}
	};
};

/** 
 * userInfo
 * 
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 * 
 * app.get('/api/user', oidc.userInfo());
 * 
 * This function returns the user info in a json object. Checks for scope and login are included.
 */
OpenIDConnect.prototype.userInfo = function() {
	var self = this;
	return [
	        self.check(true, 'openid', /profile|email/),
	        function(req, res, next) {
	        	self.client(req.session.user, function(err, id) {
	        		this.get(function(err, obj) {
	        			if(req.session.check.scopes.indexOf('profile') != -1) {
	        				delete obj.password;
	        				delete obj.openidProvider;
	        				res.json(obj);
	        			} else {
	        				res.json({email: obj.email});
	        			}
	        		});
	        	});
	        }
	        ];
};

exports.oidc = function(options) {
	return new OpenIDConnect(options);
};
