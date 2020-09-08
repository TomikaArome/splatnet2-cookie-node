/*----------*
 | Requires |
 *----------*/

const fs = require('fs');
const readline = require('readline');
const fetch = require('node-fetch');
const crypto = require('crypto');
const uuidv4 = require('uuid').v4;

/*-----------*
 | Constants |
 *-----------*/

const version = 1.0;
const clientId = '71b963c1b7b6d119';
const availableLanguages = ['en-US', 'es-MX', 'fr-CA', 'ja-JP', 'en-GB', 'es-ES', 'fr-FR', 'de-DE', 'it-IT', 'nl-NL', 'ru-RU'];

let userAgent = null;

/*-------------------*
 | Utility functions |
 *-------------------*/

const toUrlSafeBase64Encode = (val) => {
	return val.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
};

const buildQuery = (params) => {
	let r = '';
	for (let i in params) {
		if (params.hasOwnProperty(i)) {
			r += (String(i) + '=' + String(params[i]) + '&');
		}
	}
	r = r.replace(/&$/, '');
	return r;
};

const to = (promise) => {
	return Promise.resolve(promise).then(data => {
		return [null, data];
	}).catch(err => [err]);
};

// Additional require for command line only
const askQuestion = (query) => {
	const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
	return new Promise(resolve => rl.question(query, ans => {
		rl.close();
		resolve(ans);
	}));
};

/*-------------------*
 | Package functions |
 *-------------------*/

const setUserAgent = (uA) => {
	if (!uA || uA === '' || /^splatnet2-cookie-node\/[0-9\.]+(.*)$/.test(uA)) {
		throw {
			message: 'Invalid User-Agent',
			original: uA
		}
	}
	userAgent = uA;
};

const generateAuthCodeVerifier = () => {
	return toUrlSafeBase64Encode(crypto.randomBytes(32));
};

const generateAuthUri = (authCodeVerifier) => {

	// Check parameter
	if (typeof authCodeVerifier === 'undefined') {
		throw { message: 'The authCodeVerifier parameter was omitted' };
	}
	
	// Prepare
	const baseUrl = 'https://accounts.nintendo.com/connect/1.0.0/authorize';
	
	const state = toUrlSafeBase64Encode(crypto.randomBytes(36));

	const authCvHash = crypto.createHash('sha256');
	authCvHash.update(authCodeVerifier);
	const authCodeChallenge = toUrlSafeBase64Encode(authCvHash.digest());
	
	// Parameters
	let params = {
		'state':								state,
		'redirect_uri':							'npf71b963c1b7b6d119://auth',
		'client_id':							clientId,
		'scope':								'openid user user.birthday user.mii user.screenName',
		'response_type':						'session_token_code',
		'session_token_code_challenge':			authCodeChallenge,
		'session_token_code_challenge_method':	'S256',
		'theme':								'login_form'
	};
	let query = buildQuery(params);
	
	return `${baseUrl}?${query}`;
	
};

const getSessionTokenCode = (redirectUrl) => {
	let arr = redirectUrl.match(/session_token_code=(.*)&/);
	if (!arr || !arr[1]) {
		throw {
			message: 'Badly formed redirect URL',
			original: redirectUrl
		}
	}
	return arr[1];
};

const getSessionToken = async (sessionTokenCode, authCodeVerifier) => {

	// ---- STEP 1 ----
	// Get session_token from Nintendo

	const step1Url = 'https://accounts.nintendo.com/connect/1.0.0/api/session_token';
	let step1Head = {
		'User-Agent':		'OnlineLounge/1.8.0 NASDKAPI Android',
		'Accept-Language':	'en-US',
		'Accept':			'application/json',
		'Content-Type':		'application/x-www-form-urlencoded',
		'Content-Length':	'540',
		'Host':				'accounts.nintendo.com',
		'Connection':		'Keep-Alive',
		'Accept-Encoding':	'gzip'
	};
	let step1Params = {
		'client_id':					clientId,
		'session_token_code':			sessionTokenCode,
		'session_token_code_verifier':	authCodeVerifier
	};

	let [step1Err, step1Res] = await to(fetch(step1Url, {
		method: 'POST',
		headers: step1Head,
		body: buildQuery(step1Params)
	}));
	if (step1Err) {
		throw {
			message: 'The request when attempting to retrieve the session_token failed',
			original: step1Err
		};
	}
	let [step1JsonErr, step1Json] = await to(step1Res.json());
	if (step1JsonErr) {
		throw {
			message: 'The JSON retrieved from the session_token request could not be parsed',
			original: step1JsonErr
		};
	}

	if (typeof step1Json.session_token === 'undefined') {
		throw {
			message: 'Couldn\'t get the session token from Nintendo',
			original: step1Json
		};
	}
	return step1Json.session_token;

};

const getCookie = async (userLang, sessionToken) => {

	let guid = uuidv4();
	let timestamp = +new Date();

	// ---- STEP 2 ----
	// Get id_token from Nintendo

	let step2Head = {
		'Host':				'accounts.nintendo.com',
		'Accept-Encoding':	'gzip',
		'Content-Type':		'application/json; charset=utf-8',
		'Accept-Language':	userLang,
		'Content-Length':	'439',
		'Accept':			'application/json',
		'Connection':		'Keep-Alive',
		'User-Agent':		'OnlineLounge/1.8.0 NASDKAPI Android'
	};
	let step2Params = {
		'client_id':		'71b963c1b7b6d119',
		'session_token':	sessionToken,
		'grant_type':		'urn:ietf:params:oauth:grant-type:jwt-bearer-session-token'
	};
	const step2Url = 'https://accounts.nintendo.com/connect/1.0.0/api/token';

	let [step2Err, step2Res] = await to(fetch(step2Url, {
		method: 'POST',
		headers: step2Head,
		body: JSON.stringify(step2Params)
	}));
	if (step2Err) {
		throw {
			message: 'The request when attempting to retrieve the id_token failed',
			original: step2Err
		};
	}
	let [step2JsonErr, step2Json] = await to(step2Res.json());
	if (step2JsonErr) {
		throw {
			message: 'The JSON retrieved from the id_token request could not be parsed',
			original: step2JsonErr
		};
	}

	if (typeof step2Json.access_token === 'undefined') {
		throw {
			message: 'Couldn\'t get the ID token from Nintendo',
			original: step2Json
		};
	}

	let [firstFlagpCallErr, firstFlapgCall] = await to(getFromFlapgApi(step2Json.access_token, guid, timestamp, 'nso'));
	if (firstFlagpCallErr) {
		throw {
			message: 'The first call to the flapg API failed',
			original: firstFlagpCallErr
		};
	}

	// ---- STEP 3 ----
	// Get user info

	let step3Head = {
		'User-Agent':		'OnlineLounge/1.8.0 NASDKAPI Android',
		'Accept-Language':	userLang,
		'Accept':			'application/json',
		'Authorization':	`Bearer ${step2Json.access_token}`,
		'Host':				'api.accounts.nintendo.com',
		'Connection':		'Keep-Alive',
		'Accept-Encoding':	'gzip'
	};
	const step3Url = 'https://api.accounts.nintendo.com/2.0.0/users/me';

	let [step3Err, step3Res] = await to(fetch(step3Url, {
		method: 'GET',
		headers: step3Head
	}));
	if (step3Err) {
		throw {
			message: 'The request when attempting to retrieve the user info failed',
			original: step3Err
		};
	}
	let [step3JsonErr, step3Json] = await to(step3Res.json());
	if (step3JsonErr) {
		throw {
			message: 'The JSON retrieved from the user info request could not be parsed',
			original: step3JsonErr
		};
	}

	if (typeof step3Json.country === 'undefined' || typeof step3Json.birthday === 'undefined'
		|| typeof step3Json.language === 'undefined') {
		throw {
			message: 'Couldn\'t get user data from Nintendo',
			original: step3Json
		};
	}

	// ---- STEP 4 ----
	// Get the access token

	let step4Head = {
		'Host':				'api-lp1.znc.srv.nintendo.net',
		'Accept-Language':	userLang,
		'User-Agent':		'com.nintendo.znca/1.8.0 (Android/7.1.2)',
		'Accept':			'application/json',
		'X-ProductVersion':	'1.8.0',
		'Content-Type':		'application/json; charset=utf-8',
		'Connection':		'Keep-Alive',
		'Authorization':	'Bearer',
		'X-Platform':		'Android',
		'Accept-Encoding':	'gzip'
	};
	let step4Params = {
		'parameter': {
			'f':			firstFlapgCall.f,
			'naIdToken':	firstFlapgCall.p1,
			'timestamp':	firstFlapgCall.p2,
			'requestId':	firstFlapgCall.p3,
			'naCountry':	step3Json.country,
			'naBirthday':	step3Json.birthday,
			'language':		step3Json.language
		}
	};
	const step4Url = 'https://api-lp1.znc.srv.nintendo.net/v1/Account/Login';

	let [step4Err, step4Res] = await to(fetch(step4Url, {
		method: 'POST',
		headers: step4Head,
		body: JSON.stringify(step4Params)
	}));
	if (step4Err) {
		throw {
			message: 'The request when attempting to retrieve the access_token failed',
			original: step4Err
		};
	}
	let [step4JsonErr, step4Json] = await to(step4Res.json());
	if (step4JsonErr) {
		throw {
			message: 'The JSON retrieved from the access_token request could not be parsed',
			original: step4JsonErr
		};
	}

	if (typeof step4Json.result === 'undefined' || typeof step4Json.result.webApiServerCredential === 'undefined'
		|| typeof step4Json.result.webApiServerCredential.accessToken === 'undefined') {
		throw {
			message: 'Couldn\'t get the access_token from Nintendo',
			original: step4Json
		}
	}

	const step4AccessToken = step4Json.result.webApiServerCredential.accessToken;
	let [secondFlapgCallErr, secondFlapgCall] = await to(getFromFlapgApi(step4AccessToken, guid, timestamp, 'app'));
	if (secondFlapgCallErr) {
		throw {
			message: 'The second call to the flapg API failed',
			original: secondFlapgCallErr
		};
	}

	// ---- STEP 5 ----
	// Get the Splatoon access token

	let step5Head = {
		'Host':				'api-lp1.znc.srv.nintendo.net',
		'User-Agent':		'com.nintendo.znca/1.8.0 (Android/7.1.2)',
		'Accept':			'application/json',
		'X-ProductVersion':	'1.8.0',
		'Content-Type':		'application/json; charset=utf-8',
		'Connection':		'Keep-Alive',
		'Authorization':	`Bearer ${step4AccessToken}`,
		'Content-Length':	'37',
		'X-Platform':		'Android',
		'Accept-Encoding':	'gzip'
	};
	let step5Params = {
		parameter: {
			'id':					5741031244955648,
			'f':					secondFlapgCall.f,
			'registrationToken':	secondFlapgCall.p1,
			'timestamp':			secondFlapgCall.p2,
			'requestId':			secondFlapgCall.p3
		}
	};
	const step5Url = 'https://api-lp1.znc.srv.nintendo.net/v2/Game/GetWebServiceToken';

	let [step5Err, step5Res] = await to(fetch(step5Url, {
		method: 'POST',
		headers: step5Head,
		body: JSON.stringify(step5Params)
	}));
	if (step5Err) {
		throw {
			message: 'The request when attempting to retrieve the Splatoon access_token failed',
			original: step5Err
		};
	}
	let [step5JsonErr, step5Json] = await to(step5Res.json());
	if (step5JsonErr) {
		throw {
			message: 'The JSON retrieved from the Splatoon access_token request could not be parsed',
			original: step5JsonErr
		};
	}

	if (typeof step5Json.result === 'undefined'	|| typeof step5Json.result.accessToken === 'undefined') {
		throw {
			message: 'Couldn\'t get the Splatoon accessToken from Nintendo',
			original: step5Json
		};
	}
	const step5AccessToken = step5Json.result.accessToken;

	// ---- STEP 6 ----
	// Get the iksm_session cookie

	let step6Head = {
		'Host':						'app.splatoon2.nintendo.net',
		'X-IsAppAnalyticsOptedIn':	'false',
		'Accept':					'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Encoding':			'gzip,deflate',
		'X-GameWebToken':			step5AccessToken,
		'Accept-Language':			userLang,
		'X-IsAnalyticsOptedIn':		'false',
		'Connection':				'keep-alive',
		'DNT':						'0',
		'User-Agent':				'Mozilla/5.0 (Linux; Android 7.1.2; Pixel Build/NJH47D; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36',
		'X-Requested-With':			'com.nintendo.znca'
	};
	const step6Url = `https://app.splatoon2.nintendo.net/?lang=${userLang}`;

	let [step6Err, step6Res] = await to(fetch(step6Url, {
		method: 'GET',
		headers: step6Head,
		credentials: 'include'
	}));
	if (step6Err) {
		throw {
			message: 'The request when attempting to retrieve the iksm_session cookie failed',
			original: step6Err
		};
	}
	let step6Cookies = await step6Res.headers.get('Set-Cookie');

	if (!step6Cookies || !/^(.*)iksm_session=([0-9a-f]+);(.*)$/.test(step6Cookies)) {
		throw {
			message: 'Couldn\'t get the iksm_cookie',
			original: step6Cookies
		}
	}
	return step6Cookies;
	
};

const getFromFlapgApi = async (idToken, guid, timestamp, type) => {
	let hash = await getHashFromS2sApi(idToken, timestamp);
	if (!hash) { return false; }
	let head = {
		'x-token':	idToken,
		'x-time':	String(timestamp),
		'x-guid':	guid,
		'x-hash':	hash,
		'x-ver':	'3',
		'x-iid':	type
	};
	const url = 'https://flapg.com/ika2/api/login?public';

	let res = await fetch(url, {
		method: 'GET',
		headers: head
	});
	let json = await res.json();

	if (typeof json.result === 'undefined') {
		console.error('Couldn\'t get the f token from the flapg API');
		console.error(json);
		return false;
	}
	return json.result;
};

const getHashFromS2sApi = async (idToken, timestamp) => {
	// Check userAgent
	if (userAgent === null) {
		throw {
			message: 'Please set a custom User-Agent using the setUserAgent function (see: https://github.com/frozenpandaman/splatnet2statink/wiki/api-docs#integration-and-use)'
		}
	}
	//
	let head = {
		'User-Agent': userAgent,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	let params = {
		'naIdToken': idToken,
		'timestamp': timestamp
	};
	const url = 'https://elifessler.com/s2s/api/gen2';

	let res = await fetch(url, {
		method: 'POST',
		headers: head,
		body: buildQuery(params)
	});
	let json = await res.json();

	if (typeof json.hash === 'undefined') {
		console.error('Couldn\'t get the hash from the s2s API');
		console.error(json);
		return false;
	}
	return json.hash;
};

/*--------------*
 | Command line |
 *--------------*/

(async () => {
	
	// Check the process.argv array exists
	if (!process || !process.argv || !process.argv[0] || !process.argv[1]) { return 0; }

	try {

		// Init
		console.log(`splatnet2-cookie-node version ${version}\n----------`);

		// Language
		let userLangInput = await askQuestion(`Input a language from the following list: (Default: en-GB)
  Games purchased in North America:                    en-US, es-MX, fr-CA
  Games purchased in Japan:                            ja-JP
  Games purchased in Europe, Australia or New Zealand: en-GB, es-ES, fr-FR, de-DE, it-IT, nl-NL, ru-RU\n`);
		if (userLangInput === '') { userLangInput = 'en-GB'; }
		else if (availableLanguages.indexOf(userLangInput) === -1) {
			console.log('----------\nInvalid language. Exiting');
			return 0;
		}

		// Generate auth uri
		let authCodeVerifier = generateAuthCodeVerifier();
		let url = generateAuthUri(authCodeVerifier);
		console.log(`Copy and paste the following URL to your browser to login:\n----------\n${url}\n----------`);
		try {
			fs.writeFileSync('output.txt', url);
			console.log('The URL has been saved to output.txt for ease of access');
		} catch (writeErr) {
			console.error('Error trying to write the URL to output.txt');
		}

		// Redirect URL / session token code
		let redirectUrlInput = await askQuestion('----------\nInput the redirect URL obtained by right clicking on "Select this person" and pressing "Copy link address":\n');
		console.log('----------');
		let sessionTokenCode = getSessionTokenCode(redirectUrlInput);

		// Run
		let sessionToken = await getSessionToken(sessionTokenCode, authCodeVerifier);
		userAgent = `splatnet2-cookie-node/${version}`;
		let cookie = await getCookie(userLangInput, sessionToken);
		if (cookie) {
			console.log(`Cookie generated:\n----------\n${cookie}\n----------`);
			try {
				fs.writeFileSync('output.txt', cookie);
				console.log('The cookie has been saved to output.txt for ease of access');
			} catch (writeErr) {
				console.error('Error trying to write the cookie to output.txt');
			}
		}
	} catch (err) {
		console.error(err);
		return 0;
	}
	return 1;
	
})().catch((error) => {
	console.error(error);
});

/*--------*
 | Export |
 *--------*/

module.exports = {
	setUserAgent,
	generateAuthCodeVerifier,
	generateAuthUri,
	getSessionTokenCode,
	getSessionToken,
	getCookie,
	availableLanguages
};