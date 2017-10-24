(function(module) {
	"use strict";

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	var User = module.parent.require('./user'),
		Groups = module.parent.require('./groups'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),
		passportOidc = require('openid-client')['Strategy'],
		Issuer = require('openid-client')['Issuer'],
		issuerUrl, issuer, client, rpConfig,
		params = {
			scope: 'openid email',
		};

	var authenticationController = module.parent.require('./controllers/authentication');

	Issuer.defaultHttpOptions = { retries: 5, timeout: 15000 };
	issuerUrl = 'http://192.168.2.240:3010';
	issuer = new Issuer({
		issuer: issuerUrl,
		authorization_endpoint: `${issuerUrl}/auth`,
		end_session_endpoint: `${issuerUrl}/session/end`,
		token_endpoint: `${issuerUrl}/token`,
		userinfo_endpoint: `${issuerUrl}/me`,
		jwks_uri: `${issuerUrl}/certs`,
		revocation_endpoint: `${issuerUrl}/token/revocation`,
	  });
	rpConfig = { "client_id":"client-basic-mono", "client_secret":"secret-mono", "redirect_uris":[ "http://192.168.2.240:3001/login" ], "post_logout_redirect_uris":[ "http://192.168.2.240:3001/login" ] };
	client = new issuer.Client(rpConfig);
	client.CLOCK_TOLERANCE = 30; // to allow a 30 seconds skew
	
	var constants = Object.freeze({
			name: 'cloudtrust',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth2: {
				authorizationURL: 'http://192.168.2.240:3010/auth',
				tokenURL: 'http://192.168.2.240:3010/token',
				clientID: 'client-basic-bbs',	// don't change this line
				clientSecret: 'secret-bbs',	// don't change this line
				scope: 'openid', // add this for scope
			},
			userRoute: 'JSON',	// This is the address to your app's "user profile" API endpoint (expects JSON)
		}),
		configOk = false,
		OAuth = {}, passportOidc, Openid = {};

	console.log('constants############', constants);

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.userRoute) {
		winston.error('[sso-oauth] User Route required (library.js:31)');
	} else {
		configOk = true;
	}

	Openid.login = function() {
		winston.info('[login] Registering new local login strategy');
		passport.use(new passportOidc({client, params}, Openid.continueLogin));
	};

	Openid.continueLogin = function(tokenset, userinfo, next) {
		console.log('tokenset#############', tokenset)
		console.log('userinfo#############', userinfo)
	};

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOidc.prototype.userProfile = function(accessToken, done) {
				this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
					if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
					try {
						var json = JSON.parse(body);
						OAuth.parseUserReturn(json, function(err, profile) {
							if (err) return done(err);
							profile.provider = constants.name;

							done(null, profile);
						});
					} catch(e) {
						done(e);
					}
				});
			};
			passport.use(constants.name, new passportOidc({client, params}, function(tokenset, userinfo, done) {
				console.log('tokenset#############2', tokenset)
				console.log('userinfo#############2', userinfo)
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.displayName,
					email: profile.emails[0].value,
					isAdmin: profile.isAdmin
				}, function(err, user) {
					if (err) {return done(err);}
					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));
			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				// callbackURL: '/auth/' + constants.name + '/callback',
				callbackURL: 'http://192.168.2.240:4567',
				icon: 'fa-check-square',
				scope: (constants.oauth2.scope).split(',')
			});
			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(data, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		// console.log(data);

		var profile = {};
		profile.id = data.id;
		profile.displayName = data.name;
		profile.emails = [{ value: data.email }];

		// Do you want to automatically make somebody an admin? This line might help you do that...
		// profile.isAdmin = data.isAdmin ? true : false;

		// Delete or comment out the next TWO (2) lines when you are ready to proceed
		process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
		return callback(new Error('Congrats! So far so good -- please see server log for details'));

		callback(null, profile);
	}

	OAuth.login = function(payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function(err) {
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

				User.getUidByEmail(payload.email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function(oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	module.exports = OAuth;
}(module));
