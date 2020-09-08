# splatnet2-cookie-node
A nodejs package designed to obtain the `iksm_session` cookie needed to make requests to Splatnet 2 on the Nintendo Switch Online app. This is mostly just a node implementation of the python script made by [frozenpandaman](https://github.com/frozenpandaman), so most of the credit goes to him for both inspiration and his s2s API without which this package would not work.

Before using, either in command line mode or in your application as a package, please read the "Disclaimer" section at the very end.

## In the command line
This package works directly in a command line for a single-time obtaining of the iksm_session cookie. This is useful if you want to simply automatically generate an `iksm_cookie` to use Splatnet 2 in your browser.
Once you've cloned the repository, simply run `node iksm.js` and follow the instructions.

## As a package
The package exports some functions to integrate cookie generation in your own node application. I highly recommend you read up on how it works by going to [the s2s API docs](https://github.com/frozenpandaman/splatnet2statink/wiki/api-docs#how-it-works).

### Functions

**`setUserAgent(userAgent)`**

- **`userAgent`** *`String`* The user agent to be set when communicating with the s2s API.

To comply with the s2s API, you must set your own user agent header before you can use `getCookie()`. This can be done simply by running this function with the desired user agent. See [Integration and use](https://github.com/frozenpandaman/splatnet2statink/wiki/api-docs#integration-and-use) for instructions on why this matters.

**`generateAuthCodeVerifier()`**

Generates a URL safe authorisation code verifier. This function is externalised as the same authorisation code verifier is required before *and* after the user manually logs in using their Nintendo credentials.

**`generateAuthUri(authCodeVerifier)`**

- **`authCodeVerifier`** *`String`* An authorisation code verifier generated by `generateAuthCodeVerifier()`

Generates the authorisation URL where the user logs in using their Nintendo credentials.

**`getSessionTokenCode(redirectUrl)`**

- **`redirectUrl`** *`String`* The redirect URL resulting from the user logging in to their Nintendo account. This is obtained when the user right clicks on "Select this person" and presses "Copy link address".

Gets a session token code which can be used to obtain a session_token.

**`async getSessionToken(sessionTokenCode, authCodeVerifier)`**

- **`sessionTokenCode`** *`String`* A session token code obtained from `getSessionTokenCode()`
- **`authCodeVerifier`** *`String`* The same authorisation code verifier used in `generateAuthUri()` and originally generated using `generateAuthCodeVerifier()`

Gets a session token which can be used to regenerate new iksm_session cookies.

**`async getCookie(userLang, sessionToken)`**

- **`userLang`** *`String`* The language the user's game was purchased in. An array of valid languages is available in `availableLanguages`, and the list can be viewed [here](https://github.com/frozenpandaman/splatnet2statink/wiki/languages).
- **`sessionToken`** *`String`* The session token obtained from `getSessionToken()`

Generates an `iksm_session` cookie using a given session_token.

## Disclaimer

A few points to stress:
- The exact same privacy statement found in [splatnet2statink](https://github.com/frozenpandaman/splatnet2statink#automatic) applies in exactly the same way here: 
>No identifying information is ever sent to the API server. Usernames and passwords are far removed from where the API comes into play and are never readable by anyone but you. Returned hash values are never logged or stored and do not contain meaningful information. It is not possible to use either sent or stored data to identify which account/user performed a request, to view any identifying information about a user, or to gain access to an account.
- Any application that may use this package should clarify a similar disclaimer to its users before they start using it.
- I am also therefore not responsible for anything that may happen to you or your users' accounts.
- I **HIGHLY** recommend you educate yourself on how exactly the cookie is generated before you use this package. I have provided a fair few resources in this readme already. I also encourage you to study the source code in `iksm.js` (inspired directly from [`iksm.py` in splatnet2statink](https://github.com/frozenpandaman/splatnet2statink/blob/master/iksm.py)).
- If you have any more concerns, or eventual bugs that need fixing, I encourage you to contact me.