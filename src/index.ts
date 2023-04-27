import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontRequestResult } from 'aws-lambda';
import axios from 'axios';
import pino from 'pino';
import { parse, stringify } from 'querystring';
import { CookieAttributes, Cookies, SameSite, SAME_SITE_VALUES } from './util/cookie';
import { generateCSRFTokens, signedNonceHmac, urlSafe } from './util/security';

interface AuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  cookieExpirationDays?: number;
  disableCookieDomain?: boolean;
  cookieDomain?: string;
  httpOnly?: boolean;
  sameSite?: SameSite;
  logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  cookiePath?: string;
  parseAuthPath?: string;
}

interface Tokens {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
}

interface CSRFTokens {
  nonce?: string;
  nonceHmac?: string;
  pkce?: string;
  pkceHash?: string;
  state?: string;
}

export class Authenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieExpirationDays: number;
  _disableCookieDomain: boolean;
  _cookieDomain: string;
  _httpOnly: boolean;
  _sameSite?: SameSite;
  _cookieBase: string;
  _cookiePath?: string;
  _parseAuthPath?: string;
  _logger;
  _jwtVerifier;

  constructor(params: AuthenticatorParams) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppId = params.userPoolAppId;
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieExpirationDays = params.cookieExpirationDays || 365;
    this._disableCookieDomain = ('disableCookieDomain' in params && params.disableCookieDomain === true);
    this._cookieDomain = params.cookieDomain;
    this._httpOnly = ('httpOnly' in params && params.httpOnly === true);
    this._sameSite = params.sameSite;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._cookiePath = params.cookiePath;
    this._parseAuthPath = params.parseAuthPath;
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: params.userPoolId,
      clientId: params.userPoolAppId,
      tokenUse: 'id',
    });
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorects.
   */
  _verifyParams(params) {
    if (typeof params !== 'object') {
      throw new Error('Expected params to be an object');
    }
    [ 'region', 'userPoolId', 'userPoolAppId', 'userPoolDomain' ].forEach(param => {
      if (typeof params[param] !== 'string') {
        throw new Error(`Expected params.${param} to be a string`);
      }
    });
    if (params.cookieExpirationDays && typeof params.cookieExpirationDays !== 'number') {
      throw new Error('Expected params.cookieExpirationDays to be a number');
    }
    if ('disableCookieDomain' in params && typeof params.disableCookieDomain !== 'boolean') {
      throw new Error('Expected params.disableCookieDomain to be a boolean');
    }
    if ('httpOnly' in params && typeof params.httpOnly !== 'boolean') {
      throw new Error('Expected params.httpOnly to be a boolean');
    }
    if ('sameSite' in params && !SAME_SITE_VALUES.includes(params.sameSite)) {
      throw new Error('Expected params.sameSite to be a Strict || Lax || None');
    }
    if ('cookiePath' in params && typeof params.cookiePath !== 'string') {
      throw new Error('Expected params.cookiePath to be a string');
    }
  }

  /**
   * Exchange authorization code for tokens.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} code        Authorization code.
   * @return {Promise} Authenticated user tokens.
   */
  _fetchTokensFromCode(redirectURI, code): Promise<Tokens> {
    const authorization = this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString('base64');
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id:	this._userPoolAppId,
        code:	code,
        grant_type:	'authorization_code',
        redirect_uri:	redirectURI,
      }),
    } as const;
    this._logger.debug({ msg: 'Fetching tokens from grant code...', request, code });
    return axios.request(request)
      .then(resp => {
        this._logger.debug({ msg: 'Fetched tokens', tokens: resp.data });
        return {
          idToken: resp.data.id_token,
          accessToken: resp.data.access_token,
          refreshToken: resp.data.refresh_token,
        };
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to fetch tokens from grant code', request, code });
        throw err;
      });
  }

  /**
   * Fetch accessTokens from refreshToken.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} refreshToken Refresh token.
   * @return {Promise<Tokens>} Refreshed user tokens.
   */
  _fetchTokensFromRefreshToken(redirectURI: string, refreshToken: string): Promise<Tokens> {
    const authorization = this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString('base64');
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        redirect_uri: redirectURI,
      }),
    } as const;
    this._logger.debug({ msg: 'Fetching tokens from refreshToken...', request, refreshToken });
    return axios.request(request)
      .then(resp => {
        this._logger.debug({ msg: 'Fetched tokens', tokens: resp.data });
        return {
          idToken: resp.data.id_token,
          accessToken: resp.data.access_token,
        };
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to fetch tokens from refreshToken', request, refreshToken });
        throw err;
      });
  }

  _validateCSRFCookies(request: CloudFrontRequest) {
    const requestParams = parse(request.querystring);
    const requestCookies = request.headers.cookie?.flatMap(h => Cookies.parse(h.value)) || [];
    this._logger.debug({ msg: 'Validating CSRF Cookies', requestCookies});

    const parsedState = JSON.parse(
      Buffer.from(urlSafe.parse(requestParams.state), 'base64').toString()
    );

    const {nonce: originalNonce, nonceHmac, pkce} = this._getCSRFTokensFromCookie(request.headers.cookie);

    if (
      !parsedState.nonce ||
      !originalNonce ||
      parsedState.nonce !== originalNonce
    ) {
      if (!originalNonce) {
        throw new Error('Your browser didn\'t send the nonce cookie along, but it is required for security (prevent CSRF).');
      }
      throw new Error('Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)');
    }
    if (!pkce) {
      throw new Error('Your browser didn\'t send the pkce cookie along, but it is required for security (prevent CSRF).');
    }

    const calculatedHmac = signedNonceHmac(parsedState.nonce);

    if (calculatedHmac !== nonceHmac) {
      throw new Error(`Nonce signature mismatch! Expected ${calculatedHmac} but got ${nonceHmac}`);
    }
  }

  /**
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return Lambda@Edge response.
   */
  async _getRedirectResponse(tokens: Tokens, domain: string, location: string): Promise<CloudFrontRequestResult> {
    const decoded = await this._jwtVerifier.verify(tokens.idToken);
    const username = decoded['cognito:username'] as string;
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieDomain = this._disableCookieDomain ? undefined : (this._cookieDomain ? this._cookieDomain : domain);
    const cookieAttributes: CookieAttributes = {
      domain: cookieDomain,
      expires: new Date(Date.now() + this._cookieExpirationDays * 864e+5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };
    const cookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, tokens.accessToken, {...cookieAttributes, httpOnly: false}),
      Cookies.serialize(`${usernameBase}.idToken`, tokens.idToken, {...cookieAttributes, httpOnly: false}),
      ...(tokens.refreshToken ? [Cookies.serialize(`${usernameBase}.refreshToken`, tokens.refreshToken, cookieAttributes)] : []),
      Cookies.serialize(`${usernameBase}.tokenScopesString`, 'phone email profile openid aws.cognito.signin.user.admin', cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.LastAuthUser`, username, cookieAttributes),

      // Clear CSRF Token Cookies
      Cookies.serialize(`${this._cookieBase}.pkce`, '', {...cookieAttributes, domain: undefined, expires: new Date()}),
      Cookies.serialize(`${this._cookieBase}.nonce`, '', {...cookieAttributes, domain: undefined, expires: new Date()}),
      Cookies.serialize(`${this._cookieBase}.nonceHmac`, '', {...cookieAttributes, domain: undefined, expires: new Date()}),
    ];

    const response: CloudFrontRequestResult = {
      status: '302' ,
      headers: {
        'location': [{
          key: 'Location',
          value: location,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        'set-cookie': cookies.map(c => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {Tokens} Extracted id token or access token. Null if not found.
   */
  _getTokensFromCookie(cookieHeaders: Array<{ key?: string | undefined, value: string }> | undefined): Tokens {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({ msg: 'Extracting authentication token from request cookie', cookieHeaders });

    const cookies = cookieHeaders.flatMap(h => Cookies.parse(h.value));

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const idTokenCookieNamePostfix = '.idToken';
    const refreshTokenCookieNamePostfix = '.refreshToken';

    const tokens: Tokens = {};
    for (const {name, value} of cookies){
      if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(idTokenCookieNamePostfix)) {
        tokens.idToken = value;
      }
      if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(refreshTokenCookieNamePostfix)) {
        tokens.refreshToken = value;
      }
    }

    if (!tokens.idToken && !tokens.refreshToken) {
      this._logger.debug('Neither idToken, nor refreshToken was present in request cookies');
      throw new Error('Neither idToken, nor refreshToken was present in request cookies');
    }

    this._logger.debug({ msg: 'Found tokens in cookie', tokens });
    return tokens;
  }

  /**
   * Extract values of the CSRF tokens from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {CSRFTokens} Extracted CSRF Tokens from cookie.
   */
  _getCSRFTokensFromCookie(cookieHeaders: Array<{ key?: string | undefined, value: string }> | undefined): CSRFTokens {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({ msg: 'Extracting CSRF tokens from request cookie', cookieHeaders });

    const cookies = cookieHeaders.flatMap(h => Cookies.parse(h.value));

    const nonceCookieNamePostfix = '.nonce';
    const nonceHmacCookieNamePostfix = '.nonceHmac';
    const pkceCookieNamePostfix = '.pkce';

    const csrfTokens: CSRFTokens = {};
    for (const {name, value} of cookies){
      if (name.startsWith(this._cookieBase)) {
        if (name.endsWith(nonceCookieNamePostfix)) {
          csrfTokens.nonce = value;
        }
        if (name.endsWith(nonceHmacCookieNamePostfix)) {
          csrfTokens.nonceHmac = value;
        }
        if (name.endsWith(pkceCookieNamePostfix)) {
          csrfTokens.pkce = value;
        }
      }
    }

    this._logger.debug({ msg: 'Found CSRF tokens in cookie', csrfTokens });
    return csrfTokens;
  }

  /**
   * Get redirect to cognito userpool response
   * @param  {CloudFrontRequest}  request The original request
   * @param  {string}  redirectURI Redirection URI.
   * @return {CloudFrontRequestResult} Redirect response.
   */
  _getRedirectToCognitoUserPoolResponse(request: CloudFrontRequest, redirectURI: string): CloudFrontRequestResult {
    const cfDomain = request.headers.host[0].value;
    const oAuthRedirectURI = this._parseAuthPath ? `https://${cfDomain}/${this._parseAuthPath}` : redirectURI;

    const csrfTokens: CSRFTokens = generateCSRFTokens(redirectURI);

    const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${oAuthRedirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${csrfTokens.state}&scope=openid`;
    this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);

    const cookieAttributes: CookieAttributes = {
      // Expire CSRF cookies in 10 mins
      expires: new Date(Date.now() + 10*60*1000),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };
    const cookies = [
      Cookies.serialize(`${this._cookieBase}.pkce`, csrfTokens.pkce, cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.nonce`, csrfTokens.nonce, cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.nonceHmac`, csrfTokens.nonceHmac, cookieAttributes),
    ];

    return {
      status: '302',
      headers: {
        'location': [{
          key: 'Location',
          value: userPoolUrl,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        'set-cookie': cookies.map(c => ({ key: 'Set-Cookie', value: c })),
      },
    };
  }

  /**
   * Handle Lambda@Edge event:
   *   * if authentication cookie is present and valid: forward the request
   *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   */
  async handle(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = `https://${cfDomain}`;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', tokens });
      try {
        const user = await this._jwtVerifier.verify(tokens.idToken);
        this._logger.info({ msg: 'Forwarding request', path: request.uri, user });
        return request;
      } catch (err) {
        if (tokens.refreshToken) {
          this._logger.debug({ msg: 'Verifying idToken failed, verifying refresh token instead...', tokens, err });
          return await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken)
            .then(tokens => this._getRedirectResponse(tokens, cfDomain, request.uri));
        } else {
          throw err;
        }
      }
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code)
          .then(tokens => this._getRedirectResponse(tokens, cfDomain, requestParams.state as string));
      } else {
        return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
      }
    }
  }

  /**
   * 
   * 1. If the token cookies are present in the request, send users to the redirect_uri
   * 2. If cookies are not present, initiate the authentication flow
   * 
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleSignIn(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const redirectURI = requestParams.redirect_uri as string;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.debug({ msg: 'Verifying token...', tokens });
      const user = await this._jwtVerifier.verify(tokens.idToken);

      this._logger.info({ msg: 'Redirecting user to', path: redirectURI, user });
      return {
        status: '302',
        headers: {
          'location': [{
            key: 'Location',
            value: redirectURI,
          }],
        },
      };
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
    }
  }

  async handleParseAuth(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const requestParams = parse(request.querystring);
    const redirectURI = `https://${cfDomain}/${this._parseAuthPath}`;

    try {
      if (requestParams.code) {
        this._validateCSRFCookies(request);
        const tokens = await this._fetchTokensFromCode(redirectURI, requestParams.code);

        const parsedState = JSON.parse(
          Buffer.from(urlSafe.parse(requestParams.state), 'base64').toString()
        );
        this._logger.debug({msg: 'Parsed state param...', parsedState});

        return this._getRedirectResponse(tokens, cfDomain, parsedState.redirect_uri);
      } else {
        this._logger.debug({msg: 'Code param not found', requestParams});
        throw new Error('OAuth code parameter not found');
      }
    } catch (err) {
      this._logger.debug({msg: 'Unable to exchange code for tokens', err});
      return {
        status: '400',
        body: `${err}`,
      };
    }
  }

  async handleRefreshToken(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const redirectURI = `https://${this._cookieDomain}`;

    try {
      let tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.debug({ msg: 'Verifying token...', tokens });
      const user = await this._jwtVerifier.verify(tokens.idToken);

      this._logger.debug({ msg: 'Refreshing tokens...', tokens, user });
      tokens = await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken);

      this._logger.debug({ msg: 'Refreshed tokens...', tokens, user });
      return this._getRedirectResponse(tokens, cfDomain, redirectURI);
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
    }
  }

  /**
   * 
   * 
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleSignOut(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const redirectURI = requestParams.redirect_uri as string;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.debug({ msg: 'Verifying token...', tokens });
      const user = await this._jwtVerifier.verify(tokens.idToken);

      await this._revokeTokens(tokens);

      this._logger.info({ msg: 'Clearing cookies and redirecting user', path: redirectURI, user });
      return this._clearCookies(event, tokens);
    } catch (err) {
      this._logger.debug('Unable to log user out: %s', err);
      return {
        status: '302',
        headers: {
          'Location': [
            {
              key: 'Location',
              value: redirectURI,
            },
          ],
        },
      };
    }
  }

  async _revokeTokens(tokens: Tokens) {
    const authorization = this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString('base64');
    const revokeRequest = {
      url: `https://${this._userPoolDomain}/oauth2/revoke`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        token: tokens.refreshToken,
      }),
    } as const;
    this._logger.debug({ msg: 'Revoking token...', request: revokeRequest, token: tokens.refreshToken });
    return axios.request(revokeRequest)
      .then(() => {
        this._logger.debug({ msg: 'Revoked token', token: tokens.refreshToken });
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to revoke refreshToken', request: revokeRequest, err: JSON.stringify(err) });
        throw err;
      });
  }

  async _clearCookies(event: CloudFrontRequestEvent, tokens: Tokens) {
    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const requestParams = parse(request.querystring);
    const redirectURI = requestParams.redirect_uri as string;

    const decoded = await this._jwtVerifier.verify(tokens.idToken);
    const username = decoded['cognito:username'] as string;
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieDomain = this._disableCookieDomain ? undefined : (this._cookieDomain ? this._cookieDomain : cfDomain);
    const cookieAttributes: CookieAttributes = {
      domain: cookieDomain,
      expires: new Date(),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };
    const responseCookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, '', cookieAttributes),
      Cookies.serialize(`${usernameBase}.idToken`, '', cookieAttributes),
      ...(tokens.refreshToken ? [Cookies.serialize(`${usernameBase}.refreshToken`, '', cookieAttributes)] : []),
      Cookies.serialize(`${usernameBase}.tokenScopesString`, '', cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.LastAuthUser`, '', cookieAttributes),
    ];

    const response: CloudFrontRequestResult = {
      status: '302' ,
      headers: {
        'location': [{
          key: 'Location',
          value: redirectURI,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        'set-cookie': responseCookies.map(c => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }
}

