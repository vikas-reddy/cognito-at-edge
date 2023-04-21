import { CloudFrontRequest } from 'aws-lambda';
import { createHash, createHmac, randomInt } from 'crypto';


export const CONFIG = {
  secretAllowedCharacters:
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~',
  pkceLength: 43, // Should be between 43 and 128 - per spec
  nonceLength: 16,
  nonceMaxAge: 60 * 60 * 24,
  nonceSigningSecret: 'secret-from-AWS-Secret-Manager',
};

export function generateNonce() {
  const randomString = generateSecret(
    CONFIG.secretAllowedCharacters,
    CONFIG.nonceLength
  );
  const nonce = `${timestampInSeconds()}T${randomString}`;
  return nonce;
}

export function generateCSRFData(redirectURI: string) {
  const nonce = generateNonce();
  const nonceHmac = sign(nonce, CONFIG.nonceSigningSecret, CONFIG.nonceLength);

  const state = urlSafe.stringify(
    Buffer.from(
      JSON.stringify({
        nonce,
        redirect_uri: redirectURI,
      })
    ).toString('base64')
  );

  return {
    nonce,
    nonceHmac,
    state,
    ...generatePkceVerifier(),
  };
}

export function timestampInSeconds() {
  return (Date.now() / 1000) | 0;
}

export function generateSecret(allowedCharacters: string, secretLength: number) {
  return [...new Array(secretLength)]
    .map(() => allowedCharacters[randomInt(0, allowedCharacters.length)])
    .join('');
}

export function sign(
  stringToSign,
  secret,
  signatureLength,
) {
  const digest = createHmac('sha256', secret)
    .update(stringToSign)
    .digest('base64')
    .slice(0, signatureLength);
  const signature = urlSafe.stringify(digest);
  return signature;
}

export const urlSafe = {
  /*
        Functions to translate base64-encoded strings, so they can be used:
        - in URL's without needing additional encoding
        - in OAuth2 PKCE verifier
        - in cookies (to be on the safe side, as = + / are in fact valid characters in cookies)

        stringify:
            use this on a base64-encoded string to translate = + / into replacement characters

        parse:
            use this on a string that was previously urlSafe.stringify'ed to return it to
            its prior pure-base64 form. Note that trailing = are not added, but NodeJS does not care
    */
  stringify: (b64encodedString) =>
    b64encodedString.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
  parse: (b64encodedString) =>
    b64encodedString.replace(/-/g, '+').replace(/_/g, '/'),
};

export function generatePkceVerifier() {
  const pkce = generateSecret(
    CONFIG.secretAllowedCharacters,
    CONFIG.pkceLength
  );
  const verifier = {
    pkce,
    pkceHash: urlSafe.stringify(
      createHash('sha256').update(pkce, 'utf8').digest('base64')
    ),
  };
  return verifier;
}

export function parseCookie(req: CloudFrontRequest): {[name: string]: string} {
  const cookies = {};
  if (!req.headers.cookie) {
    return cookies;
  }
  req.headers.cookie[0].value
    .split(';')
    .map(c => c.trim().split('='))
    .forEach(([k,v]) => cookies[k] = v);
  return cookies;
}

/*
export async function getTokenPayload(token, type = 'access') {
  const verifier = CognitoJwtVerifier.create({
    userPoolId: 'us-east-1_0Y6ErGRis',
    tokenUse: type,
    clientId: '4lbg303mvhhou3hak20o8on1fa',
  });

  const payload = await verifier.verify(token);
  return payload;
}
*/
