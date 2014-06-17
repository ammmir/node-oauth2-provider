# OAuth 2 Server with OpenID Connect support

This is a fully functional OAuth 2 server implementation, with support for OpenID Connect specification. Based on https://github.com/ammmir/node-oauth2-provider.

## News

Major rewrite. Now we use [modelling](https://www.npmjs.org/package/modelling) for Model part.

## Install

Install via npm:

    npm install openid-connect

You can add it to your Connect or Express application as another middleware.
Be sure to enable the `bodyParser` and `query` middleware.

To use it inside your project, just do:

```
var oidc = require('openid-connect').oidc(options);
```

and then, for example, with express

```
app.get('/authorization', oidc.auth());
```
## Options

When you require openid-connect, you may specify options. If you specify them, it must be with a json object with the following properties (all of them are optional):

* __login_url__

  URL where login form can be found. Defaults to _"/login"_.

* __consent_url__

  URL where consent form can be found. Defaults to _"/consent"_.

* __scopes__

  Json object of type { _scope name_: _scope description_, ... } used to define custom scopes. 

* __models__

  Models as described in [modelling](https://www.npmjs.org/package/modelling).
  
  Actually OpenIDConnect defines 6 models:
  
  * _user_: Where user data is stored (email, password, etc).
  * _client_: Where user can register a client app that will use your project for authentication/authorization.
  * _consent_: Where user consent of certain scopes for a particular client is stored.
  * _auth_: Where authorization data is stored (token, expiration date, etc).
  * _access_: Where access data is stored (token, expiration date, etc).
  * _refresh_: Where refresh data is stored (token, expiration date, etc).

  You can overwrite any part of any model of OpenIDConnect, or overwrite all of them.
  
  If you overwrite user model, the new model _should_ conform with [OpenID Connect Standard Claims](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), in order to comply with the spec.
  
* __adapters__
  
  Adapters as described in [modelling](https://www.npmjs.org/package/modelling).
  
* __connections__
  
  Connections as described in [modelling](https://www.npmjs.org/package/modelling).
  
* __policies__
  
  Policies as described in [modelling](https://www.npmjs.org/package/modelling).
  
* __alien__

  You can use your own Waterline collections with OpenIDConnect. 
  
  If you define an alien collection with the same name of one of the models in OpenIDConnect, the last one will be replaced.
  
  For example:
  
  ```
  var orm = new Waterline();
  
  var MyUserModel = Waterline.collection.extend({
  	identity: 'user',
  	//Collection definition here.
  });
  
  var MyUsersCarModel = Waterline.collection.extend({
  	identity: 'car',
  	//Collection definition here.
  });
  
  var config = {
	collections: {
		user: MyUserModel, //replace OpenIDConnect user model. 
		car: MyUsersCarModel //add new model
	}
  }
  
  orm.initialize(config, function(err, result) {
  	var options = {
  		alien: result.collections
  	}
  
  	var oidc = require('openid-connect').oidc(options);
  
  	app.get('/cars', oidc.use(['user', 'car']), function(req, res, next) {
  		...
  	});
  });
  ```
  
  __Beware__ that if you replace an OpenIDConnect model, you won't be able to use _populate_ with other OpenIDConnect models.
  
  If you replace user model, the new model _should_ conform with [OpenID Connect Standard Claims](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), in order to comply with the spec.

* __orm__

  You can replace the whole OpenIDConnect modelling instance with your own. 
  
  __Beware__ that you __must__ implement at _least_ all models and exept for `user` model, all attributes. 
  
  If in your models, you set `autoPK` to false, they __must__ have an `id` attribute that is primary key.
  
  _Notice_ that you can get OpenIDConnect's default models with `require('openid-connect').defaults().models`.
  
  ```
  var orm = new modelling(options);
  
  var oidc = require('openid-connect').oidc({orm: orm});
  ```

## API

* **auth()**

  returns a function to be placed as middleware in connect/express routing methods. For example:

  ```
  app.get('/authorization', oidc.auth());
  ```
 
  This is the authorization endpoint, as described in [http://tools.ietf.org/html/rfc6749#section-3.1](http://tools.ietf.org/html/rfc6749#section-3.1)

* **consent()**

  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  ```
  app.post('/consent', oidc.consent());
  ```
 
  This method saves the consent of the resource owner to a client request, or returns an access_denied error.

* **token()**

  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  ```
  app.get('/token', oidc.token());
  ```
 
  This is the token endpoint, as described in [http://tools.ietf.org/html/rfc6749#section-3.2](http://tools.ietf.org/html/rfc6749#section-3.2)

* **check(scope, ...)**
 
  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  ```
  app.get('/api/user', oidc.check('openid', /profile|email/), function(req, res, next) { ... });
  ```

  If no arguments are given, checks if user is logged in.
 
  Arguments may be of type _string_ or _regexp_.
 
  This function is used to check if user logged in, if an access_token is present, and if certain scopes where granted to it.


* **userInfo()**

  returns a function to be placed as middleware in connect/express routing methods. For example:

  ```
  app.get('/api/user', oidc.userInfo());
  ```

  This function returns the user info in a json object. Checks for scope and login are included.

* **use([name])**

  Same description as in [modelling](https://www.npmjs.org/package/modelling). If you defined _alien_ models or your own _orm_ you can call those models as well.
  
* **getOrm()**

  Retrieves current _orm_ of instance.
 
## Example

There is a complete example [here](https://github.com/agmoyano/OpenIDConnect/tree/master/examples).

## Help!

Any suggestions, bug reports, bug fixes, pull requests, etc, are very wellcome ([here](https://github.com/agmoyano/OpenIDConnect/issues)). 

Thanks for reading!.
