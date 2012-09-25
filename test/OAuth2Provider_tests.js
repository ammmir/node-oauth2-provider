var sinon = require('sinon'),
  should = require('chai').should,
  serializer = require('serializer');

describe('OAuth2Provider', function(){
  it('should inherit from EventEmitter', function(){
  // rneeds to be in here since static constructor depends on creating
  // secure serializer
  var oAuth2Provider = createOauth2Provider();

  oAuth2Provider.should.be.a('EventEmitter');
  });

  describe('login', function(){
    beforeEach(function(){
      // stub returned serializer so that can mock it

      this.createSerializerStub = sinon.stub(serializer, 'createSecureSerializer'); 
      this.emitterStub = sinon.stub('EventEmitter'),
      this.oAuth2Provider = createOauth2Provider();
    });
    afterEach(function(){
      this.createSerializerStub.restore();
      this.emitterStub.restore();
    });
    var accessTokenKey = 'access_token';
    // for backwards compatibility
    it('should emit access_token if it can be parsed from request', function(done){
      oAuth2Provider.login();
    });
    it('should write error to response if cannot parse access token', function(done){

    });
  });

  // utility methods
  var createOauth2Provider = function(crypt_key, sign_key){
    var crypt_key = crypt_key || '123131',
      sign_key = sign_key || 'asdfasdfas';

    sinon.stub()

    // requiring this needs module needs to be done repeatedly, since it depends on a static serializer
    // factory in its static constructuro, which needs to be stubbed by many of the methods
    var OAuth2Provider = require('../index'),
      oAuth2Provider = new OAuth2Provider(crypt_key, sign_key);
    return oAuth2Provider;
  };
});