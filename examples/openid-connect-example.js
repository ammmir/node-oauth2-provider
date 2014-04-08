
/**
 * Module dependencies.
 */

var crypto = require('crypto')
  , express = require('express')
  , expressSession = require('express-session')
  , http = require('http')
  , path = require('path')
  , querystring = require('querystring')
  , rs = require('connect-redis')(expressSession)
  , extend = require('extend')
  , test = {
		status: 'new'
	};

var app = express();

  var options = {
    login_url: '/my/login',
    consent_url: '/user/consent',
    scopes: {
      foo: 'Access to foo special resource',
      bar: 'Access to bar special resource'
    },
    app: app
  };
  var oidc = require('../index').oidc(options);
  //, serializer = require('serializer').createSecureSerializer('fiajfopasfjaso234ujfaisfjoi', 'fsakjfu39ur98u38uugoeukjaerwui8w');



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
  var inputs = '<input type="text" name="email" placeholder="Enter Email"/><input type="password" name="password" placeholder="Enter Password"/>';
  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
  var body = '<body><h1>Login</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
});

//process login
app.post('/my/login', oidc.use('user'), function(req, res, next) {
  delete req.session.error;
  req.model.user.findOne({email: req.body.email}, function(err, user) {
	  if(!err && user && user.samePassword(req.body.password)) {
		  req.session.user = user.id;
		  res.redirect(req.param('return_url')||'/user');
	  } else {
		  req.session.error = 'User or password incorrect.';
		  res.redirect(req.path); 
	  }
  });
});

app.all('/logout', function(req, res, next) {
	delete req.session.user;
	res.redirect('/my/login');
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
  var body = '<body><h1>Consent</h1><form method="POST">'+ul+'<input type="submit" name="accept" value="Accept"/><input type="submit" name="cancel" value="Cancel"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
});

//process user consent form
app.post('/user/consent', oidc.consent());

//user creation form
app.get('/user/create', function(req, res, next) {
  var head = '<head><title>Sign in</title></head>';
  var inputs = '';
  //var fields = mkFields(oidc.model('user').attributes);
  var fields = {
		  given_name: {
			  label: 'Given Name',
			  type: 'text'
		  },
		  middle_name: {
			  label: 'Middle Name',
			  type: 'text'
		  },
		  family_name: {
			  label: 'Family Name',
			  type: 'text'
		  },
		  email: {
			  label: 'Email',
			  type: 'email'
		  },
		  password: {
			  label: 'Password',
			  type: 'password'
		  },
		  passConfirm: {
			  label: 'Confirm Password',
			  type: 'password'
		  }
  };
  for(var i in fields) {
    inputs += '<div><label for="'+i+'">'+fields[i].label+'</label><input type="'+fields[i].type+'" placeholder="'+fields[i].label+'" id="'+i+'"  name="'+i+'"/></div>';
  }
  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
  var body = '<body><h1>Sign in</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
  res.send('<html>'+head+body+'</html>');
});

//process user creation
app.post('/user/create', oidc.use('user'), function(req, res, next) {
  delete req.session.error;
  req.model.user.findOne({email: req.body.email}, function(err, user) {
	  if(err) {
		  req.session.error=err;
	  } else if(user) {
		  req.session.error='User already exists.';
	  }
	  if(req.session.error) {
		  res.redirect(req.path);
	  } else {
		  req.body.name = req.body.given_name+' '+(req.body.middle_name?req.body.middle_name+' ':'')+req.body.family_name;
		  req.model.user.create(req.body, function(err, user) {
			 if(err || !user) {
				 req.session.error=err?err:'User could not be created.';
				 res.redirect(req.path);
			 } else {
				 req.session.user = user.id;
				 res.redirect('/user');
			 }
		  }); 
	  }
  });
});

app.get('/user', oidc.check(), function(req, res, next){
  res.send('<h1>User Page</h1><div><a href="/client">See registered clients of user</a></div>');
});

//User Info Endpoint
app.get('/api/user', oidc.userInfo());

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
app.get('/client/register', oidc.check(), oidc.use('client'), function(req, res, next) {
  
  var mkId = function() {
	var key = crypto.createHash('md5').update(req.session.user+'-'+Math.random()).digest('hex');
	req.model.client.findOne({key: key}, function(err, client) {
      if(!err && !client) {
    	  var secret = crypto.createHash('md5').update(key+req.session.user+Math.random()).digest('hex');
    	  req.session.register_client = {};
		  req.session.register_client.key = key;
		  req.session.register_client.secret = secret;
		  var head = '<head><title>Register Client</title></head>';
		  var inputs = '';
		  var fields = {
			    name: {
					label: 'Client Name',
					html: '<input type="text" id="name" name="name" placeholder="Client Name"/>'
				},
				redirect_uris: {
					label: 'Redirect Uri',
					html: '<input type="text" id="redirect_uris" name="redirect_uris" placeholder="Redirect Uri"/>'
				},
				key: {
					label: 'Client Key',
					html: '<span>'+key+'</span>'
				},
				secret: {
					label: 'Client Secret',
					html: '<span>'+secret+'</span>'
				}
		  };
		  for(var i in fields) {
			inputs += '<div><label for="'+i+'">'+fields[i].label+'</label> '+fields[i].html+'</div>';
		  }
		  var error = req.session.error?'<div>'+req.session.error+'</div>':'';
		  var body = '<body><h1>Register Client</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
		  res.send('<html>'+head+body+'</html>');
      } else if(!err) {
    	  mkId();
      } else {
    	  next(err);
      }
    });
  };
  mkId();
});

//process client register
app.post('/client/register', oidc.check(), oidc.use('client'), function(req, res, next) {
	delete req.session.error;
  req.body.key = req.session.register_client.key;
  req.body.secret = req.session.register_client.secret;
  req.body.user = req.session.user;
  req.body.redirect_uris = req.body.redirect_uris.split(/[, ]+/); 
  req.model.client.create(req.body, function(err, client){
    if(!err && client) {
      res.redirect('/client/'+client.id);
    } else {
      next(err);
    }
  });
});

app.get('/client', oidc.check(), oidc.use('client'), function(req, res, next){
  var head ='<h1>Clients Page</h1><div><a href="/client/register"/>Register new client</a></div>';
  req.model.client.find({user: req.session.user}, function(err, clients){
	 var body = ["<ul>"];
	 clients.forEach(function(client) {
		body.push('<li><a href="/client/'+client.id+'">'+client.name+'</li>'); 
	 });
	 body.push('</ul>');
	 res.send(head+body.join(''));
  });
  
});

app.get('/client/:id', oidc.check(), oidc.use('client'), function(req, res, next){
  req.model.client.findOne({user: req.session.user, id: req.params.id}, function(err, client){
	  if(err) {
		  next(err);
	  } else if(client) {
		  var html = '<h1>Client '+client.name+' Page</h1><div><a href="/client">Go back</a></div><ul><li>Key: '+client.key+'</li><li>Secret: '+client.secret+'</li><li>Redirect Uris: <ul>';
		  client.redirect_uris.forEach(function(uri){
			 html += '<li>'+uri+'</li>'; 
		  });
		  html+='</ul></li></ul>';
		  
		  res.send(html);
	  } else {
		  res.send('<h1>No Client Fount!</h1><div><a href="/client">Go back</a></div>');
	  }
  });
});

app.get('/test/clear', function(req, res, next){
	test = {status: 'new'};
	res.redirect('/test');
});

app.get('/test', oidc.use('client'), function(req, res, next) {
	var html='<h1>Test Auth Flows</h1>';
	var resOps = {
			"/user/foo": "Restricted by foo scope",
			"/user/bar": "Restricted by bar scope",
			"/user/and": "Restricted by 'bar and foo' scopes",
			"/user/or": "Restricted by 'bar or foo' scopes",
			"/api/user": "User Info Endpoint"
	};
	var mkinputs = function(name, desc, type, value, options) {
		var inp = '';
		switch(type) {
		case 'select':
			inp = '<select id="'+name+'" name="'+name+'">';
			for(var i in options) {
				inp += '<option value="'+i+'"'+(value&&value==i?' selected':'')+'>'+options[i]+'</option>';
			}
			inp += '</select>';
			inp = '<div><label for="'+name+'">'+(desc||name)+'</label>'+inp+'</div>';
			break;
		default:
			if(options) {
				for(var i in options) {
					inp +=  '<div>'+
								'<label for="'+name+'_'+i+'">'+options[i]+'</label>'+
								'<input id="'+name+'_'+i+' name="'+name+'" type="'+(type||'radio')+'" value="'+i+'"'+(value&&value==i?' checked':'')+'>'+
							'</div>';
				}
			} else {
				inp = '<input type="'+(type||'text')+'" id="'+name+'"  name="'+name+'" value="'+(value||'')+'">';
				if(type!='hidden') {
					inp = '<div><label for="'+name+'">'+(desc||name)+'</label>'+inp+'</div>';
				}
			}
		}
		return inp;
	};
	switch(test.status) {
	case "new":
		req.model.client.find().populate('user').exec(function(err, clients){
			var inputs = [];
			inputs.push(mkinputs('response_type', 'Auth Flow', 'select', null, {code: 'Auth Code', "id_token token": 'Implicit'}));
			var options = {};
			clients.forEach(function(client){
				options[client.key+':'+client.secret]=client.user.id+' '+client.user.email+' '+client.key+' ('+client.redirect_uris.join(', ')+')';
			});
			inputs.push(mkinputs('client_id', 'Client Key', 'select', null, options));
			//inputs.push(mkinputs('secret', 'Client Secret', 'text'));
			inputs.push(mkinputs('scope', 'Scopes', 'text'));
			inputs.push(mkinputs('nonce', 'Nonce', 'text', 'N-'+Math.random()));
			test.status='1';
			res.send(html+'<form method="GET">'+inputs.join('')+'<input type="submit"/></form>');
		});
		break;
	case '1':
		req.query.redirect_uri=req.protocol+'://'+req.headers.host+req.path;
		extend(test, req.query);
		req.query.client_id = req.query.client_id.split(':')[0]; 
		test.status = '2';
		res.redirect('/user/authorize?'+querystring.stringify(req.query));
		break;
	case '2':
		extend(test, req.query);
		if(test.response_type == 'code') {
			test.status = '3';
			var inputs = [];
			//var c = test.client_id.split(':');
			inputs.push(mkinputs('code', 'Code', 'text', req.query.code));
			/*inputs.push(mkinputs('grant_type', null, 'hidden', 'authorization_code'));
			inputs.push(mkinputs('client_id', null, 'hidden', c[0]));
			inputs.push(mkinputs('client_secret', null, 'hidden', c[1]));
			inputs.push(mkinputs('redirect_uri', null, 'hidden', test.redirect_uri));*/
			res.send(html+'<form method="GET">'+inputs.join('')+'<input type="submit" value="Get Token"/></form>');
		} else {
			test.status = '4';
			html += "Got: <div id='data'></div>";
    		var inputs = [];
			//var c = test.client_id.split(':');
			inputs.push(mkinputs('access_token', 'Access Token', 'text'));
			inputs.push(mkinputs('page', 'Resource to access', 'select', null, resOps));
			
			var after = 
				"<script>" +
					"document.getElementById('data').innerHTML = window.location.hash; " +
					"var h = window.location.hash.split('&'); " +
					"for(var i = 0; i < h.length; i++) { " +
						"var p = h[i].split('='); " +
						"if(p[0]=='access_token') { " +
							"document.getElementById('access_token').value = p[1]; " +
							"break; " +
						"} " +
					"}" +
				"</script>";
			/*inputs.push(mkinputs('grant_type', null, 'hidden', 'authorization_code'));
			inputs.push(mkinputs('client_id', null, 'hidden', c[0]));
			inputs.push(mkinputs('client_secret', null, 'hidden', c[1]));
			inputs.push(mkinputs('redirect_uri', null, 'hidden', test.redirect_uri));*/
			res.send(html+'<form method="GET">'+inputs.join('')+'<input type="submit" value="Get Resource"/></form>'+after);
		}
		break;
	case '3':
		test.status = '4';
		test.code = req.query.code;
		var query = {
				grant_type: 'authorization_code',
				code: test.code,
				redirect_uri: test.redirect_uri
		};
		var post_data = querystring.stringify(query);
		var post_options = {
			port: app.get('port'),
			path: '/user/token',
			method: 'POST',
			headers: {
			    'Content-Type': 'application/x-www-form-urlencoded',
			    'Content-Length': post_data.length,
			    'Authorization': 'Basic '+Buffer(test.client_id, 'utf8').toString('base64'),
			    'Cookie': req.headers.cookie
		    }
		};
		
		// Set up the request
		var post_req = http.request(post_options, function(pres) {
		    pres.setEncoding('utf8');
		    var data = '';
		    pres.on('data', function (chunk) {
		    	data += chunk;
		    	console.log('Response: ' + chunk);
		    });
		    pres.on('end', function(){
		    	console.log(data);
		    	try {
		    		data = JSON.parse(data);
		    		html += "Got: <pre>"+JSON.stringify(data)+"</pre>";
		    		var inputs = [];
					//var c = test.client_id.split(':');
					inputs.push(mkinputs('access_token', 'Access Token', 'text', data.access_token));
					inputs.push(mkinputs('page', 'Resource to access', 'select', null, resOps));
					/*inputs.push(mkinputs('grant_type', null, 'hidden', 'authorization_code'));
					inputs.push(mkinputs('client_id', null, 'hidden', c[0]));
					inputs.push(mkinputs('client_secret', null, 'hidden', c[1]));
					inputs.push(mkinputs('redirect_uri', null, 'hidden', test.redirect_uri));*/
					res.send(html+'<form method="GET">'+inputs.join('')+'<input type="submit" value="Get Resource"/></form>');
		    	} catch(e) {
		    		res.send('<div>'+data+'</div>');
		    	}
		    });
		});
		
		// post the data
		post_req.write(post_data);
		post_req.end();
		break;
//res.redirect('/user/token?'+querystring.stringify(query));
	case '4':
		test = {status: 'new'};
		res.redirect(req.query.page+'?access_token='+req.query.access_token);
	}
	
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
