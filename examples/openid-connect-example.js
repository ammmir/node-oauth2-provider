
/**
 * Module dependencies.
 */

var express = require('express')
  , http = require('http')
  , path = require('path')
  , querystring = require('querystring')
  , rs = require('connect-redis')(express);
  
  var options = {
    login_url: '/my/login',
    consent_url: '/user/consent',
    scopes: {
      foo: 'Access to foo special resource',
      bar: 'Access to bar special resource'
    },
    redis_prefix: 'some:prefix'
  };
  var oidc = require('../index').oidc(options);
  //, serializer = require('serializer').createSecureSerializer('fiajfopasfjaso234ujfaisfjoi', 'fsakjfu39ur98u38uugoeukjaerwui8w');

var app = express();

// all environments
app.set('port', process.env.PORT || 3001);
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser('Some Secret!!!'));
app.use(express.session({store: new rs({host: '127.0.0.1', port: 6379, client: oidc.redisClient}), secret: 'Some Secret!!!'}));
app.use(app.router);

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

//redirect to login
app.get('/', function(req, res) {
  res.redirect('/my/login');
});

//Login form (I use email as user name)
app.get('/my/login', function(req, res, next) {
  var head = '<head><title>Login</title></head>';
  var inputs = '<input type="text" name="user" placeholder="Enter Email"/><input type="password" name="password" placeholder="Enter Password"/>';
  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
  var body = '<body><h1>Login</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
});

//process login
app.post('/my/login', function(req, res, next) {
  delete req.session.error;
  oidc.searchUser(req.body.user, function(err, uid){
    if(!err && uid) {
      this.getPassword(function(err, storedpwd){
	if(storedpwd == req.body.password) {
	  req.session.user = uid;
	  if(req.query.return_url || req.body.return_url) {
	    res.redirect(req.query.return_url || req.body.return_url);
	  }
	} else {
	  req.session.error = 'User or password incorrect.';
	  res.redirect(req.path);
	}
      });
    } else {
	req.session.error = 'User or password incorrect.';
	res.redirect(req.path);      
    }
  }); 
});

//authorization endpoint
app.get('/user/authorize', oidc.auth());

//token endpoint
app.post('/user/token', oidc.token());

//user consent form
app.get('/user/consent', function(req, res, next) {
  var head = '<head><title>Consent</title></head>';
  var lis = [];
  for(var i in req.session.scopes) {
    lis.push('<li><b>'+i+'</b>: '+req.session.scopes[i].explain+'</li>');
  }
  var ul = '<ul>'+lis.join('')+'</ul>';
  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
  var body = '<body><h1>Consent</h1><form method="POST">'+ul+'<input type="submit" name="accept" value="Accept"/><input type="cancel" name="cancel" value="Cancel"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
});

//process user consent form
app.post('/user/consent', oidc.consent());

//user creation form
app.get('/user/create', function(req, res, next) {
  var head = '<head><title>Sign in</title></head>';
  var inputs = '';
  var fields = mkFields(oidc.getUserParams());
  for(var i in fields) {
    inputs += '<div><label for="'+i+'">'+fields[i].label+'</label>'+fields[i].html+'</div>';
  }
  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
  var body = '<body><h1>Sign in</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
}, routes.create_user);

//process user creation
app.post('/user/create', function(req, res, next) {
  delete req.session.error
  oidc.searchUser(req.body.email, function(err, user) {
    if(!err && user) {
      req.session.error='User already exists';
      res.redirect(req.path);
    } else {
      req.body.name = req.body.given_name+' '+req.body.middle_name+' '+req.body.family_name;
      oidc.user(req.body, function(err, id){
	if(!err && id) {
	  req.session.user = id;
	  res.redirect('/user');
	} else {
	  next(err);
	}
      });
    }
  });
});

app.get('/user', oidc.check(), function(req, res, next){
  res.send('<h1>User Page</h1>');
});

app.get('/user/foo', oidc.check('foo'), function(req, res, next){
  res.send('<h1>Page Restricted by foo scope</h1>');
});

app.get('/user/bar', oidc.check('bar'), function(req, res, next){
  res.send('<h1>Page restricted by bar scope</h1>');
});

app.get('/user/and', oidc.check('bar', 'foo'), function(req, res, next){
  res.send('<h1>Page restricted by "bar and foo" scopes</h1>');
});

app.get('/user/or', oidc.check(/bar|foo/), function(req, res, next){
  res.send('<h1>Page restricted by "bar or foo" scopes</h1>');
});

//Client register form
app.get('/client/register', oidc.check(), function(req, res, next) {
  var params=oidc.getClientParams();
  var mkId = function(id) {
    oidc.searchClient(id, function(err, client) {
      if(!err && !client) {
	params.id.value = id;
	params.secret.value = req.session.user+Math.random();
	req.session.register_client.id = id;
	req.session.register_client.secret = params.secret.value;
	var head = '<head><title>Register Client</title></head>';
	var inputs = '';
	var fields = mkFields(params);
	for(var i in fields) {
	  inputs += '<div><label for="'+i+'">'+fields[i].label+'</label>'+fields[i].html+'</div>';
	}
	var error = req.session.error?'<div>'+req.session.error+'</div>':'';
	var body = '<body><h1>Register Client</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
	res.send('<html>'+head+body+'</html>');
      } else if(!err) {
	mkId(req.session.user+Math.random());
      } else {
	next(err);
      }
    });
  };
  mkId(req.session.user+Math.random());
}, routes.create_client);

//process client register
app.post('/client/register', oidc.check(), function(req, res, next) {
  req.body.id = req.session.register_client.id;
  req.body.secret = req.session.register_client.secret;
  req.body.user = req.session.user;
  oidc.client(req.body, function(err, id){
    if(id) {
      oidc.user(req.session.user).setRefClients(this);
      res.redirect('/client');
    } else {
      next(err);
    }
  });
});

app.get('/client', oidc.check(), function(req, res, next){
  res.send('<h1>client page</h1>');
});

function mkFields(params) {
  var fields={};
  for(var i in params) {
    if(params[i].html) {
      fields[i] = {};
      fields[i].label = params[i].label||(i.charAt(0).toUpperCase()+i.slice(1)).replace(/_/g, ' ');
      switch(params[i].html) {
	case 'password':
	  fields[i].html = '<input class="form-control" type="password" id="'+i+'" name="'+i+'" placeholder="'+fields[i].label+'"'+(params[i].mandatory?' required':'')+'/>';
	  break;
	case 'date':
	  fields[i].html = '<input class="form-control" type="date" id="'+i+'" name="'+i+'"'+(params[i].mandatory?' required':'')+'/>';
	  break;
	case 'hidden':
	  fields[i].html = '<input class="form-control" type="hidden" id="'+i+'" name="'+i+'"/>';
	  fields[i].label = false;
	  break;
	case 'fixed':
	  fields[i].html = '<span class="form-control">'+params[i].value+'</span>';
	  break;
	case 'radio':
	  fields[i].html = '';
	  for(var j=0; j<params[i].ops; j++) {
	    fields[i].html += '<input class="form-control" type="radio" id="'+i+'_'+j+'" name="'+i+'" '+(params[i].mandatory?' required':'')+'/> '+params[i].ops[j];
	  }
    break;
	default:
	  fields[i].html = '<input class="form-control" type="text" id="'+i+'" name="'+i+'" placeholder="'+fields[i].label+'"'+(params[i].mandatory?' required':'')+'/>';
	  break;
      }
    }
  }
  return fields;
}

 var clearErrors = function(req, res, next) {
   delete req.session.error;
   next();
 };

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});