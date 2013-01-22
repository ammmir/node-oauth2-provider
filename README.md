# OAuth 2 Provider for Connect & Express

This is a node.js module for implementing OAuth2 servers (providers)
that support server-side (code) and client-side (token) OAuth flows.

It's very customizable, so you can (and currently, must) take care of
OAuth token storage and client lists. In the future, a Mongo or Redis
backed abstraction will be provided so you don't need to care about
any kind of storage at all.

## Using it with npm

If you're using this module via npm, please be sure the bracket the
version in your app's `package.json` file. Major versions may have an
incompatible API that's not backwards-compatible, so use a safe version
range under `dependencies` (eg. for version 1.x):

    "oauth2-provider": "1.x"

## Quick Start

Install via npm:

    npm install oauth2-provider

You can add it to your Connect or Express application as another middleware.
Be sure to enable the `bodyParser` and `query` middleware.

The OAuth2Provider instance providers two middleware:

* `oauth()`: OAuth flow entry and access token generation
* `login()`: Access control for protected resources

The most importand event emitted by OAuth2Provider is `access_token`, which
lets you set up the request as if it were authenticated. For example, to
support both cookie-authenticated and OAuth access to protected URLs, you
could populate `req.session.user` so that individual URLs don't need to
care about which type of authentication was used.

To support client authentication (sometimes known as xAuth) for trusted
clients, handle the `client_auth` event to exchange a username and password
for an access token. See `examples/simple_express3.js`.

## Example

In the root directory, run `npm install express` and then run:

    node examples/simple_express3.js

Visit <http://localhost:8081/login> to gain access to
<http://localhost:8081/secret> or use OAuth to obtain an access token as a code (default) or a token (in the URL hash):

  - code: <http://localhost:8081/oauth/authorize?client_id=1&redirect_uri=http://myapp.foo/>
  - token: <http://localhost:8081/oauth/authorize?client_id=1&redirect_uri=http://myapp.foo/&response_type=token>

## Running tests

  Install dev dependencies:
  
    $ npm install -d

  Run the tests:

    $ make test
