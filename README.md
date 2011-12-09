# OAuth 2 Provider for Connect & Express

WARNING: If you're using this module via npm, be sure to use a specific
version in your `package.json` since until this module reaches 1.x there
will be breaking changes in both npm and master. Stable releases are
tagged on GitHub, so use those versions to pull down a specific one from
npm.

This is a node.js module for implementing OAuth2 servers (providers)
that support server-side (code) and client-side (token) OAuth flows.

It's very customizable, so you can (and currently, must) take care of
OAuth token storage and client lists. In the future, a Mongo or Redis
backed abstraction will be provided so you don't need to care about
any kind of storage at all.

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

See examples/simple.js for how to use it.
