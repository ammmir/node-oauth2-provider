# OAuth 2 Provider with support for OpenID/Connect specification

This is an OAuth 2 server implementation with support for OpenID/Connect specification

## Install

Install via npm:

    npm install OpenIDConnect

You can add it to your Connect or Express application as another middleware.
Be sure to enable the `bodyParser` and `query` middleware.

To use it inside your project, just do:

```
var oidc = require('OpenIDConnect').oidc();
```

and then, for example, with express

```
app.get('/authorization', oidc.auth());
```

## API

* ### auth()

  returns a function to be placed as middleware in connect/express routing methods. For example:

 `app.get('/authorization', oidc.auth());`
 
  This is the authorization endpoint, as described in [http://tools.ietf.org/html/rfc6749#section-3.1](http://tools.ietf.org/html/rfc6749#section-3.1)

* ### consent()

  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  `app.post('/consent', oidc.consent());`
 
  This method saves the consent of the resource owner to a client request, or returns an access_denied error.

* ### token()

  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  `app.get('/token', oidc.token());`
 
  This is the token endpoint, as described in [http://tools.ietf.org/html/rfc6749#section-3.2](http://tools.ietf.org/html/rfc6749#section-3.2)

* ###check([scopes])
 
  returns a function to be placed as middleware in connect/express routing methods. For example:
 
  `app.get('/api/user', oidc.check(['openid', 'profile']), function(req, res, next) { ... });`
 
  This function is used to check if an access_token is present, and if certain scopes where granted to it.

## Example

Complete example soon.
