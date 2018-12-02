const jwt = require('jsonwebtoken');
const promisify = require('util.promisify');
const jwtVerify = promisify(jwt.verify);

async function VerifyJWT(jwks, jwt, audience, issuer) {
  var keys = jwks.keys
  const signingKeys = keys
      .filter(key => key.use === 'sig' && key.kty === 'RSA' && key.kid && ((key.x5c && key.x5c.length) || (key.n && key.e)))
      .map(key => {
        if (key.x5c && key.x5c.length) {
          return { kid: key.kid, nbf: key.nbf, publicKey: certToPEM(key.x5c[0]) };
        } else {
          return { kid: key.kid, nbf: key.nbf, rsaPublicKey: rsaPublicKeyToPEM(key.n, key.e) };
        }
      });
  for (var j=0;j<signingKeys.length;j++) {
    let key = signingKeys[j].publicKey || signingKeys[j].rsaPublicKey;
    try {
      return await jwtVerify(jwt, key, { audience, issuer });
    } catch (err) {
      if (/invalid signature/.test(err.message)) {
        continue
      } else {
        continue
      }
    }
  }
  return false;
}

function toHex(number) {
  const nstr = number.toString(16);
  if (nstr.length % 2) {
    return `0${nstr}`;
  }
  return nstr;
}

function encodeLengthHex(n) {
  if (n <= 127) {
    return toHex(n);
  }
  const nHex = toHex(n);
  const lengthOfLengthByte = 128 + nHex.length / 2;
  return toHex(lengthOfLengthByte) + nHex;
}

function prepadSigned(hexStr) {
  const msb = hexStr[0];
  if (msb < '0' || msb > '7') {
    return `00${hexStr}`;
  }
  return hexStr;
}

function rsaPublicKeyToPEM(modulusB64, exponentB64) {
  const modulus = Buffer.from(modulusB64, 'base64');
  const exponent = Buffer.from(exponentB64, 'base64');
  const modulusHex = prepadSigned(modulus.toString('hex'));
  const exponentHex = prepadSigned(exponent.toString('hex'));
  const modlen = modulusHex.length / 2;
  const explen = exponentHex.length / 2;

  const encodedModlen = encodeLengthHex(modlen);
  const encodedExplen = encodeLengthHex(explen);
  const encodedPubkey = '30' +
    encodeLengthHex(modlen + explen + encodedModlen.length / 2 + encodedExplen.length / 2 + 2) +
    '02' + encodedModlen + modulusHex +
    '02' + encodedExplen + exponentHex;

  const der = Buffer.from(encodedPubkey, 'hex')
    .toString('base64');

  let pem = `-----BEGIN RSA PUBLIC KEY-----\n`;
  pem += `${der.match(/.{1,64}/g).join('\n')}`;
  pem += `\n-----END RSA PUBLIC KEY-----\n`;
  return pem;
};

module.exports = VerifyJWT;
