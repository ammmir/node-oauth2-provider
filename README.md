# OAuth 2 Server with OpenID Connect support

This is an fully functional OAuth 2 server implementation, with support for OpenID Connect specification. Based on https://github.com/ammmir/node-oauth2-provider.

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

* __redis_prefix__

  prefix for redis keys. Defaults to _"oidc:"_.

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

* **getClientParams()**

  Returns an object with params defined in **_obj** property of client namespace. See <https://github.com/agmoyano/redis-modelize>.

* **getUserParams()**

  Returns an object with params defined in **_obj** property of user namespace. See <https://github.com/agmoyano/redis-modelize>.

* **searchClient(parts, callback)**

  Executes *reverse* method of client namespace. See <https://github.com/agmoyano/redis-modelize>.

* **searchUser(parts, callback)**

  Executes *reverse* method of user namespace. See <https://github.com/agmoyano/redis-modelize>. 

* **client(params, callback)**

  Constructor of client namespace. See <https://github.com/agmoyano/redis-modelize>. 

* **user(params, callback)**

  Constructor of user namespace. See <https://github.com/agmoyano/redis-modelize>. 
 
## Example

There is a complete example [here](https://github.com/agmoyano/OpenIDConnect/tree/master/examples).
